"""
PhishGuard AI - Database Service
Manages interactions with MongoDB collections: users, scans, and model_metadata.
Supports local MongoDB, MongoDB Atlas, and safe graceful degradation when offline.
"""
from datetime import datetime, timedelta
import logging
from typing import Any, Dict, List, Optional
from bson import ObjectId

logger = logging.getLogger("phishguard.database")


class DatabaseService:
    """
    MongoDB service layer with automatic index creation, CRUD operations,
    and aggregate metrics generation.
    """

    def __init__(self, mongo_uri: str, db_name: str = "phishguard"):
        self.mongo_uri = mongo_uri
        self.db_name = db_name
        self.client = None
        self.db = None
        self._connected = False
        self._init_connection()

    def _init_connection(self):
        try:
            from pymongo import MongoClient
            from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError

            self.client = MongoClient(
                self.mongo_uri,
                serverSelectionTimeoutMS=2000,
                connectTimeoutMS=2000
            )
            # Verify connectivity with ping
            self.client.admin.command("ping")
            self.db = self.client[self.db_name]
            self._connected = True
            logger.info(f"Connected to MongoDB database '{self.db_name}' successfully.")
            self.ensure_indexes()
        except Exception as e:
            self._connected = False
            self.db = None
            logger.warning(f"MongoDB connection unavailable: {e}. Running in offline/standalone mode.")

    def is_connected(self) -> bool:
        """Check if database connection is alive."""
        if not self._connected or self.client is None:
            return False
        try:
            self.client.admin.command("ping")
            return True
        except Exception:
            self._connected = False
            return False

    def ensure_indexes(self):
        """Creates indexes for queries and uniqueness."""
        if not self.is_connected():
            return
        try:
            from pymongo import ASCENDING, DESCENDING
            self.db.users.create_index([("email", ASCENDING)], unique=True)
            self.db.scans.create_index([("user_id", ASCENDING), ("scanned_at", DESCENDING)])
            self.db.scans.create_index([("scanned_at", DESCENDING)])
            self.db.scans.create_index([("url", ASCENDING)])
            logger.info("Database indexes verified/created.")
        except Exception as e:
            logger.error(f"Failed to create MongoDB indexes: {e}")

    # =========================================================================
    # User Operations
    # =========================================================================

    def create_user(self, name: str, email: str, password_hash: str, role: str = "user") -> Optional[str]:
        """Creates a new user record."""
        if not self.is_connected():
            logger.error("Cannot create user: Database disconnected.")
            return None
        user_doc = {
            "name": name.strip(),
            "email": email.lower().strip(),
            "password_hash": password_hash,
            "role": role,
            "created_at": datetime.utcnow()
        }
        try:
            result = self.db.users.insert_one(user_doc)
            return str(result.inserted_id)
        except Exception as e:
            logger.error(f"Error creating user {email}: {e}")
            return None

    def find_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        """Finds user by lowercase email address."""
        if not self.is_connected():
            return None
        try:
            doc = self.db.users.find_one({"email": email.lower().strip()})
            if doc:
                doc["_id"] = str(doc["_id"])
            return doc
        except Exception as e:
            logger.error(f"Error finding user by email: {e}")
            return None

    def find_user_by_id(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Finds user by ObjectId string."""
        return self.get_user_by_id(user_id)

    def get_user_by_id(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Finds user by string ObjectId."""
        if not self.is_connected():
            return None
        try:
            doc = self.db.users.find_one({"_id": ObjectId(user_id)})
            if doc:
                doc["_id"] = str(doc["_id"])
            return doc
        except Exception as e:
            logger.error(f"Error finding user by id {user_id}: {e}")
            return None

    def get_all_users(self) -> List[Dict[str, Any]]:
        """Returns all users with password hashes stripped."""
        if not self.is_connected():
            return []
        try:
            cursor = self.db.users.find({}, {"password_hash": 0}).sort("created_at", -1)
            users = []
            for u in cursor:
                u["_id"] = str(u["_id"])
                users.append(u)
            return users
        except Exception as e:
            logger.error(f"Error fetching users: {e}")
            return []

    def update_user_role(self, user_id: str, new_role: str) -> bool:
        """Updates user authorization role ('user' or 'admin')."""
        if not self.is_connected():
            return False
        try:
            res = self.db.users.update_one(
                {"_id": ObjectId(user_id)},
                {"$set": {"role": new_role}}
            )
            return res.modified_count > 0
        except Exception as e:
            logger.error(f"Error updating user role: {e}")
            return False

    def get_user_count(self) -> int:
        if not self.is_connected():
            return 0
        try:
            return self.db.users.count_documents({})
        except Exception:
            return 0

    # =========================================================================
    # Scan Operations
    # =========================================================================

    def save_scan(self, user_id: Optional[str], url: str, classification: str,
                  risk_score: int, probability: float, features: Dict[str, Any]) -> Optional[str]:
        """Saves an analysis record."""
        if not self.is_connected():
            return None
        scan_doc = {
            "user_id": str(user_id) if user_id else None,
            "url": url,
            "classification": classification,
            "risk_score": int(risk_score),
            "probability": float(probability),
            "features": features,
            "scanned_at": datetime.utcnow()
        }
        try:
            result = self.db.scans.insert_one(scan_doc)
            return str(result.inserted_id)
        except Exception as e:
            logger.error(f"Error saving scan: {e}")
            return None

    def get_scan_by_id(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Fetches a scan document by ObjectId."""
        if not self.is_connected():
            return None
        try:
            doc = self.db.scans.find_one({"_id": ObjectId(scan_id)})
            if doc:
                doc["_id"] = str(doc["_id"])
            return doc
        except Exception as e:
            logger.error(f"Error getting scan {scan_id}: {e}")
            return None

    def delete_scan(self, scan_id: str, user_id: str) -> bool:
        """Deletes a scan if it belongs to the user."""
        if not self.is_connected():
            return False
        try:
            res = self.db.scans.delete_one({"_id": ObjectId(scan_id), "user_id": str(user_id)})
            return res.deleted_count > 0
        except Exception as e:
            logger.error(f"Error deleting scan: {e}")
            return False

    def get_user_scans(self, user_id: str, limit: int = 50, skip: int = 0,
                       search: Optional[str] = None, classification: Optional[str] = None,
                       page: Optional[int] = None, page_size: Optional[int] = None,
                       filter_classification: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieves scans for a specific user with filtering and pagination."""
        if not self.is_connected():
            return []

        # Handle page / page_size parameters if passed
        if page is not None and page_size is not None:
            skip = max(0, (page - 1) * page_size)
            limit = page_size

        filter_cls = filter_classification or classification

        query: Dict[str, Any] = {"user_id": str(user_id)}
        if search:
            query["url"] = {"$regex": search, "$options": "i"}
        if filter_cls and filter_cls != "all":
            query["classification"] = filter_cls

        try:
            cursor = self.db.scans.find(query).sort("scanned_at", -1).skip(skip).limit(limit)
            scans = []
            for s in cursor:
                s["_id"] = str(s["_id"])
                scans.append(s)
            return scans
        except Exception as e:
            logger.error(f"Error fetching scans for user {user_id}: {e}")
            return []

    def count_user_scans(self, user_id: str, search: Optional[str] = None,
                         filter_classification: Optional[str] = None) -> int:
        """Alias for count of user scans."""
        return self.get_user_scan_count(user_id, search=search, classification=filter_classification)

    def get_user_scan_count(self, user_id: str, search: Optional[str] = None,
                            classification: Optional[str] = None) -> int:
        """Counts scans for a specific user with query filter."""
        if not self.is_connected():
            return 0
        query: Dict[str, Any] = {"user_id": str(user_id)}
        if search:
            query["url"] = {"$regex": search, "$options": "i"}
        if classification and classification != "all":
            query["classification"] = classification
        try:
            return self.db.scans.count_documents(query)
        except Exception:
            return 0

    def get_user_scans_since(self, user_id: str, since: datetime) -> List[Dict[str, Any]]:
        """Fetches all scans for a user since a given datetime."""
        if not self.is_connected():
            return []
        try:
            cursor = self.db.scans.find({
                "user_id": str(user_id),
                "scanned_at": {"$gte": since}
            }).sort("scanned_at", 1)
            scans = []
            for s in cursor:
                s["_id"] = str(s["_id"])
                scans.append(s)
            return scans
        except Exception as e:
            logger.error(f"Error in get_user_scans_since: {e}")
            return []

    def get_user_scan_stats(self, user_id: str) -> Dict[str, int]:
        """Returns stats mapped with keys expected by dashboard_routes."""
        st = self.get_user_stats(user_id)
        return {
            "total": st.get("total_scans", 0),
            "safe": st.get("safe_count", 0),
            "suspicious": st.get("suspicious_count", 0),
            "phishing": st.get("phishing_count", 0),
            "avg_risk": st.get("avg_risk", 0)
        }

    def get_user_stats(self, user_id: str) -> Dict[str, Any]:
        """Calculates aggregate statistics for a user's dashboard."""
        default_stats = {
            "total_scans": 0,
            "safe_count": 0,
            "suspicious_count": 0,
            "phishing_count": 0,
            "avg_risk": 0
        }
        if not self.is_connected():
            return default_stats

        try:
            pipeline = [
                {"$match": {"user_id": str(user_id)}},
                {
                    "$group": {
                        "_id": None,
                        "total_scans": {"$sum": 1},
                        "avg_risk": {"$avg": "$risk_score"},
                        "safe_count": {
                            "$sum": {"$cond": [{"$eq": ["$classification", "Likely Safe"]}, 1, 0]}
                        },
                        "suspicious_count": {
                            "$sum": {"$cond": [{"$eq": ["$classification", "Suspicious"]}, 1, 0]}
                        },
                        "phishing_count": {
                            "$sum": {"$cond": [{"$eq": ["$classification", "Likely Phishing"]}, 1, 0]}
                        }
                    }
                }
            ]
            res = list(self.db.scans.aggregate(pipeline))
            if res:
                r = res[0]
                return {
                    "total_scans": r.get("total_scans", 0),
                    "safe_count": r.get("safe_count", 0),
                    "suspicious_count": r.get("suspicious_count", 0),
                    "phishing_count": r.get("phishing_count", 0),
                    "avg_risk": round(r.get("avg_risk", 0.0), 1)
                }
            return default_stats
        except Exception as e:
            logger.error(f"Error calculating user stats: {e}")
            return default_stats

    def get_all_scans(self, page: int = 1, page_size: int = 20) -> List[Dict[str, Any]]:
        """Returns scans across all users for admin review."""
        if not self.is_connected():
            return []
        try:
            skip = (page - 1) * page_size
            cursor = self.db.scans.find({}).sort("scanned_at", -1).skip(skip).limit(page_size)
            scans = []
            for s in cursor:
                s["_id"] = str(s["_id"])
                scans.append(s)
            return scans
        except Exception as e:
            logger.error(f"Error in get_all_scans: {e}")
            return []

    def get_global_scan_stats(self) -> Dict[str, int]:
        """Calculates global system metrics for the admin dashboard."""
        default_stats = {
            "total_users": 0,
            "total_scans": 0,
            "phishing_count": 0,
            "safe_count": 0,
            "suspicious_count": 0
        }
        if not self.is_connected():
            return default_stats

        try:
            total_users = self.db.users.count_documents({})
            pipeline = [
                {
                    "$group": {
                        "_id": None,
                        "total_scans": {"$sum": 1},
                        "safe_count": {
                            "$sum": {"$cond": [{"$eq": ["$classification", "Likely Safe"]}, 1, 0]}
                        },
                        "suspicious_count": {
                            "$sum": {"$cond": [{"$eq": ["$classification", "Suspicious"]}, 1, 0]}
                        },
                        "phishing_count": {
                            "$sum": {"$cond": [{"$eq": ["$classification", "Likely Phishing"]}, 1, 0]}
                        }
                    }
                }
            ]
            agg = list(self.db.scans.aggregate(pipeline))
            if agg:
                res = agg[0]
                return {
                    "total_users": total_users,
                    "total_scans": res.get("total_scans", 0),
                    "phishing_count": res.get("phishing_count", 0),
                    "safe_count": res.get("safe_count", 0),
                    "suspicious_count": res.get("suspicious_count", 0)
                }
            return {
                "total_users": total_users,
                "total_scans": 0,
                "phishing_count": 0,
                "safe_count": 0,
                "suspicious_count": 0
            }
        except Exception as e:
            logger.error(f"Error calculating global stats: {e}")
            return default_stats

    # =========================================================================
    # Model Metadata Operations
    # =========================================================================

    def save_model_metadata(self, metadata: Dict[str, Any]) -> Optional[str]:
        """Persists model training information in database."""
        if not self.is_connected():
            return None
        try:
            metadata["recorded_at"] = datetime.utcnow()
            res = self.db.model_metadata.insert_one(metadata)
            return str(res.inserted_id)
        except Exception as e:
            logger.error(f"Error saving model metadata: {e}")
            return None

    def get_model_metadata(self) -> Optional[Dict[str, Any]]:
        """Retrieves most recent model metadata."""
        if not self.is_connected():
            return None
        try:
            doc = self.db.model_metadata.find_one({}, sort=[("recorded_at", -1)])
            if doc:
                doc["_id"] = str(doc["_id"])
            return doc
        except Exception as e:
            logger.error(f"Error getting model metadata: {e}")
            return None

# PhishGuard AI - Dataset

## Overview

The dataset used for PhishGuard AI contains labeled URLs for binary classification into legitimate (benign) and phishing categories.

## Dataset Structure

The dataset is stored in standard CSV format with two columns:

| Column | Data Type | Description |
| :--- | :--- | :--- |
| `url` | String | Complete URL including protocol scheme (`http://` or `https://`) |
| `label` | Integer | Binary class: `0` = Benign / Legitimate, `1` = Phishing |

### Format Example

```csv
url,label
https://www.google.com/search?q=machine+learning,0
https://en.wikipedia.org/wiki/Phishing,0
http://paypal-security-update.account-verify.xyz/login,1
http://192.168.1.100/admin/secure/signin.php,1
```

## Included Sample Dataset

The file `sample_dataset.csv` contains 400 labeled sample URLs (200 benign, 200 phishing). This dataset is provided for development, automated testing, and demonstration during project evaluations.

## Using Production Datasets

For real-world evaluation and high-scale benchmarking, replace `sample_dataset.csv` with standard academic phishing datasets:

1. **PhiUSIIL Phishing URL Dataset** (UCI Machine Learning Repository):
   - Over 235,000 URLs with balanced labels.
   - Reference: https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset
2. **ISCX-URL 2016 Dataset** (University of New Brunswick):
   - Over 120,000 URLs categorized into benign, phishing, malware, and defacement.
   - Reference: https://www.unb.ca/cic/datasets/url-2016.html

### Retraining with a New Dataset

Once you place your CSV in `dataset/` or specify its path:

```bash
python ml/train_model.py --dataset dataset/your_dataset.csv
```

## Security & Ethics Notice

- All phishing URLs in the sample dataset are fictional or point to documentation/test domains.
- PhishGuard AI never fetches or executes content from user-submitted URLs.
- Machine learning predictions are probabilistic risk estimates, not definitive security guarantees.

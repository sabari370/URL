/**
 * PhishGuard AI - Dashboard Visualizations
 * Renders 7-day activity timeline and classification distribution using Chart.js.
 */

document.addEventListener('DOMContentLoaded', () => {
    const rawData = window.chartData || {};
    const dailyCounts = rawData.daily_counts || { labels: [], datasets: { safe: [], suspicious: [], phishing: [] } };
    const classDist = rawData.class_dist || { labels: [], values: [] };

    // 1. Activity Bar / Line Chart
    const activityCanvas = document.getElementById('activityChart');
    if (activityCanvas) {
        const ctx = activityCanvas.getContext('2d');
        new Chart(ctx, {
            type: 'bar',
            data: {
                labels: dailyCounts.labels || [],
                datasets: [
                    {
                        label: 'Likely Safe',
                        data: dailyCounts.datasets.safe || [],
                        backgroundColor: 'rgba(16, 185, 129, 0.75)',
                        borderColor: '#10b981',
                        borderWidth: 1,
                        borderRadius: 4
                    },
                    {
                        label: 'Suspicious',
                        data: dailyCounts.datasets.suspicious || [],
                        backgroundColor: 'rgba(245, 158, 11, 0.75)',
                        borderColor: '#f59e0b',
                        borderWidth: 1,
                        borderRadius: 4
                    },
                    {
                        label: 'Likely Phishing',
                        data: dailyCounts.datasets.phishing || [],
                        backgroundColor: 'rgba(239, 68, 68, 0.75)',
                        borderColor: '#ef4444',
                        borderWidth: 1,
                        borderRadius: 4
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    x: {
                        stacked: false,
                        grid: { color: 'rgba(30, 41, 59, 0.5)' },
                        ticks: { color: '#94a3b8' }
                    },
                    y: {
                        beginAtZero: true,
                        grid: { color: 'rgba(30, 41, 59, 0.5)' },
                        ticks: {
                            color: '#94a3b8',
                            stepSize: 1,
                            precision: 0
                        }
                    }
                },
                plugins: {
                    legend: {
                        labels: { color: '#cbd5e1', font: { family: 'Inter', size: 12 } }
                    }
                }
            }
        });
    }

    // 2. Classification Distribution Doughnut Chart
    const distCanvas = document.getElementById('distributionChart');
    if (distCanvas) {
        const ctx = distCanvas.getContext('2d');
        const values = classDist.values || [0, 0, 0];
        const hasData = values.some(v => v > 0);

        new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: classDist.labels.length ? classDist.labels : ['Likely Safe', 'Suspicious', 'Likely Phishing'],
                datasets: [{
                    data: hasData ? values : [1, 1, 1],
                    backgroundColor: hasData
                        ? ['#10b981', '#f59e0b', '#ef4444']
                        : ['rgba(30,41,59,0.5)', 'rgba(30,41,59,0.5)', 'rgba(30,41,59,0.5)'],
                    borderColor: '#13192a',
                    borderWidth: 3
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: '70%',
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: { color: '#cbd5e1', boxWidth: 12, padding: 15 }
                    },
                    tooltip: {
                        enabled: hasData
                    }
                }
            }
        });
    }
});

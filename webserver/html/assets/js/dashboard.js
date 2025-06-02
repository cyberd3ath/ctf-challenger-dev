import {messageManager, apiClient} from './utils.js';
import themeToggle from './theme-toggle.js';

class Dashboard {
    constructor() {
        this.progressChart = null;
        this.categoryChart = null;
        this.timelineChart = null;
        this.timeSpentInterval = null;
        this.unsubscribeTheme = themeToggle.subscribe(() => this.updateChartColors());
    }

    async init() {
        document.addEventListener('DOMContentLoaded', async () => {
            this.handleSuccessMessage();
            await this.initializeCharts();
            await this.loadDashboardData();
            this.setupEventListeners();
        });
    }

    handleSuccessMessage() {
        const successMessage = sessionStorage.getItem('ctfCreationSuccess');
        if (successMessage) {
            messageManager.showSuccess(successMessage);
            sessionStorage.removeItem('ctfCreationSuccess');
        }
    }

    async initializeCharts() {
        const progressCtx = document.getElementById('progressChart').getContext('2d');
        this.progressChart = this.initProgressChart(progressCtx);
        this.categoryChart = this.initCategoryChart();
        this.timelineChart = this.initTimelineChart();
    }

    async loadDashboardData() {
        try {
            const data = await apiClient.get('../backend/dashboard.php');
            if (!data) return;

            if (data.success) {
                this.updateAllComponents(data.data);
            } else {
                this.handleDataLoadError(data);
            }
        } catch (error) {
            console.error('Error fetching dashboard data:', error);
        }
    }

    updateAllComponents(data) {
        this.updateUserInfo(data.user);
        this.updateProgressData(this.progressChart, data.progress);
        this.updateCategoryChart(data.category);
        this.updateTimelineChart(data.timeline);
        this.updateRecentActivity(data.activity);
        this.updateBadges(data.badges);
        this.updateActiveChallenge(data.active_challenge);
        this.updateRecommendedChallenges(data.challenges);
        this.updateNews(data.news);
    }

    handleDataLoadError(data) {
        console.error('Failed to load dashboard data:', data.message);
        if (data.redirect) {
            window.location.href = data.redirect;
        }
    }

    initProgressChart(ctx) {
        return new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['Solved', 'Failed', 'Unsolved'],
                datasets: [{
                    data: [30, 20, 50],
                    backgroundColor: ['#00adb5', '#f44336', 'rgba(255, 255, 255, 0.1)'],
                    borderWidth: 0
                }]
            },
            options: {
                cutout: '70%',
                plugins: {legend: {display: false}}
            }
        });
    }

    initCategoryChart() {
        const container = document.querySelector("#categoryChart");
        container.innerHTML = `
            <div class="category-bars-container">
                ${['crypto', 'forensics', 'pwn', 'reverse', 'web', 'misc'].map(category => `
                    <div class="category-bar ${category}">
                        <div class="category-label">${category.charAt(0).toUpperCase() + category.slice(1)}</div>
                        <div class="progress-container">
                            <div class="progress-track">
                                <div class="progress-fill" style="width: 0%"></div>
                            </div>
                            <div class="progress-value">0%</div>
                        </div>
                    </div>
                `).join('')}
            </div>
        `;

        return {
            updateSeries: (percentages) => {
                percentages = percentages || {};
                ['crypto', 'forensics', 'pwn', 'reverse', 'web', 'misc'].forEach(category => {
                    const percentage = Math.min(100, Math.max(0, Math.round(Number(percentages[category]) || 0)));
                    const fill = document.querySelector(`#categoryChart .${category} .progress-fill`);
                    const valueEl = document.querySelector(`#categoryChart .${category} .progress-value`);

                    if (fill) fill.style.width = `${percentage}%`;
                    if (valueEl) valueEl.textContent = `${percentage}%`;
                });
            }
        };
    }

    updateChartColors() {
        const colorText = getComputedStyle(document.documentElement)
            .getPropertyValue('--color-text').trim();

        console.log("Current text color:", colorText);


        if (this.timelineChart) {
            this.timelineChart.options.plugins.legend.labels.color = colorText;
            this.timelineChart.options.scales.x.ticks.color = colorText;
            this.timelineChart.options.scales.y.ticks.color = colorText;
            this.timelineChart.options.scales.y1.ticks.color = colorText;
            this.timelineChart.update();
        }
    }

    initTimelineChart() {
        const ctx = document.getElementById('timelineChart').getContext('2d');
        return new Chart(ctx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [
                    {
                        label: 'Points Earned',
                        data: [],
                        borderColor: '#00adb5',
                        backgroundColor: 'rgba(0, 173, 181, 0.1)',
                        borderWidth: 2,
                        fill: true,
                        tension: 0.3,
                        pointBackgroundColor: '#00adb5',
                        pointRadius: 5,
                        pointHoverRadius: 7,
                        yAxisID: 'y'
                    },
                    {
                        label: 'Challenges Solved',
                        data: [],
                        borderColor: '#f5abb9',
                        backgroundColor: 'rgba(245, 171, 185, 0.1)',
                        borderWidth: 2,
                        fill: true,
                        tension: 0.3,
                        pointBackgroundColor: '#f5abb9',
                        pointRadius: 5,
                        pointHoverRadius: 7,
                        yAxisID: 'y1'
                    }
                ]
            },
            options: {
                responsive: true,
                interaction: {mode: 'index', intersect: false},
                plugins: {
                    tooltip: {
                        callbacks: {
                            label: (context) => {
                                let label = context.dataset.label || '';
                                if (label) label += ': ';
                                label += context.datasetIndex === 0
                                    ? `${context.raw} points`
                                    : `${context.raw} challenge${context.raw !== 1 ? 's' : ''}`;
                                return label;
                            }
                        }
                    },
                    legend: {
                        position: 'top',
                        labels: {
                            color: getComputedStyle(document.documentElement).getPropertyValue('--color-text').trim(),
                            usePointStyle: true
                        }
                    }
                },
                scales: {
                    x: {
                        grid: {color: 'rgba(255, 255, 255, 0.05)'},
                        ticks: {color: 'rgba(255, 255, 255, 0.7)'}
                    },
                    y: {
                        title: {display: true, text: 'Points', color: '#00adb5'},
                        position: 'left',
                        grid: {color: 'rgba(255, 255, 255, 0.05)'},
                        ticks: {color: 'rgba(255, 255, 255, 0.7)'}
                    },
                    y1: {
                        title: {display: true, text: 'Challenges', color: '#f5abb9'},
                        position: 'right',
                        grid: {drawOnChartArea: false},
                        ticks: {
                            color: 'rgba(255, 255, 255, 0.7)',
                            precision: 0
                        }
                    }
                }
            }
        });
    }

    updateUserInfo(userData) {
        document.getElementById('username').textContent = userData.username;
        document.getElementById('user-rank').textContent = `#${userData.rank}`;
        document.getElementById('user-points').textContent = userData.points.toLocaleString();
    }

    updateProgressData(chart, progressData) {
        chart.data.datasets[0].data = [
            progressData.solved,
            progressData.failed,
            progressData.unsolved
        ];
        chart.update();

        document.getElementById('solved-count').textContent = progressData.solved;
        document.getElementById('success-rate').textContent = `${progressData.success_rate}%`;
        document.getElementById('avg-time').textContent = progressData.avg_time;
    }

    updateCategoryChart(progressData) {
        this.categoryChart.updateSeries(progressData.percentages);
    }

    updateTimelineChart(timelineData) {
        this.timelineChart.data.labels = timelineData.labels;
        this.timelineChart.data.datasets[0].data = timelineData.points;
        this.timelineChart.data.datasets[1].data = timelineData.challenges;
        this.timelineChart.update();
    }

    updateRecentActivity(activities) {
        const activityList = document.querySelector('.activity-list');
        activityList.innerHTML = '';

        activities.forEach(activity => {
            const item = document.createElement('div');
            item.className = 'list-item';
            item.dataset.challengeId = activity.challenge_id;
            item.dataset.status = activity.status;
            item.setAttribute('tabindex', '0');
            item.setAttribute('role', 'button');
            item.setAttribute('aria-label', `View ${activity.challenge} details`);

            const {icon, statusText} = this.getActivityStatusInfo(activity);

            item.innerHTML = `
                <div class="activity-icon">${icon}</div>
                <div class="activity-content">
                    <div class="activity-title">${activity.challenge}</div>
                    <div class="activity-meta">
                        ${activity.category} • ${activity.time_ago} • ${statusText}
                    </div>
                </div>
                <div class="activity-arrow">→</div>
            `;

            this.setupActivityItemClickHandler(item, activity.challenge_id);
            activityList.appendChild(item);
        });
    }

    getActivityStatusInfo(activity) {
        switch (activity.status) {
            case 'solved':
                return {icon: '✅', statusText: `+${activity.points} points`};
            case 'failed':
                return {icon: '⚠️', statusText: `${activity.attempts} attempts`};
            case 'active':
                return {icon: '⌛', statusText: 'In progress'};
            default:
                return {icon: '🔍', statusText: 'Started'};
        }
    }

    setupActivityItemClickHandler(item, challengeId) {
        const handleClick = () => {
            window.location.href = `/challenge?id=${challengeId}`;
        };

        item.addEventListener('click', handleClick);
        item.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                handleClick();
            }
        });
    }

    updateBadges(badgesData) {
        const badgesGrid = document.querySelector('.badges-grid');
        badgesGrid.innerHTML = '';

        badgesData.earned.forEach(badge => {
            const badgeItem = document.createElement('div');
            badgeItem.className = 'badge-item';
            badgeItem.setAttribute('data-tooltip', badge.description);

            badgeItem.innerHTML = `
            <div class="badge-icon ${badge.color || 'gold'}">${badge.icon || '🏆'}</div>
            <div class="badge-title">${badge.name}</div>
            `;
            badgesGrid.appendChild(badgeItem);
        });

        this.updateBadgeProgress(badgesData.next_badge);
    }

    updateBadgeProgress(nextBadge) {
        const progressBar = document.querySelector('.badges-progress .progress-fill');
        const progressText = document.querySelector('.badges-progress .progress-text');

        if (nextBadge) {
            progressBar.style.width = `${nextBadge.progress}%`;
            progressText.textContent =
                `${nextBadge.progress}% to ${nextBadge.name} • ` +
                `${nextBadge.solved_count} challenges solved`;
        }
    }

    updateRecommendedChallenges(challenges) {
        const challengesList = document.querySelector('.challenges-list');
        challengesList.innerHTML = '';

        challenges.forEach(challenge => {
            const challengeItem = document.createElement('div');
            challengeItem.className = 'list-item';

            challengeItem.innerHTML = `
            <div class="status-indicator ${challenge.difficulty}"></div>
            <div class="challenge-content">
                <div class="challenge-title">${challenge.name}</div>
                <div class="challenge-meta">
                    ${challenge.category} • ${challenge.points} points • ${challenge.success_rate}
                </div>
            </div>
            <a href="/challenge?id=${challenge.id}" class="button button-secondary">Start</a>
            `;

            challengesList.appendChild(challengeItem);
        });
    }

    updateNews(newsItems) {
        const newsList = document.querySelector('.news-list');
        newsList.innerHTML = '';

        newsItems.forEach(news => {
            const item = document.createElement('div');
            item.className = 'news-item';
            item.innerHTML = `
                <div class="news-date">${this.formatNewsDate(news.created_at)}</div>
                <div class="news-content">
                    <h3>${news.title}</h3>
                    <p>${news.short_description}</p>
                </div>
            `;
            newsList.appendChild(item);
        });
    }

    formatNewsDate(dateString) {
        const date = new Date(dateString);
        const now = new Date();
        const diffInDays = Math.floor((now - date) / (1000 * 60 * 60 * 24));

        if (diffInDays === 0) return 'Today';
        if (diffInDays === 1) return 'Yesterday';
        if (diffInDays < 7) return `${diffInDays} days ago`;
        return date.toLocaleDateString('en-US', {month: 'short', day: 'numeric'});
    }

    showChallengeDetails(range, index, challenges) {
        const popup = document.getElementById('challengeDetailsPopup');
        const dateLabel = document.getElementById('popupDate');
        const challengeList = document.getElementById('challengeList');

        const date = this.getDateForRange(range, index);
        dateLabel.textContent = this.formatPopupDate(date, range);

        challengeList.innerHTML = '';
        if (!challenges || challenges.length === 0) {
            challengeList.innerHTML = '<li>No challenges solved this day</li>';
        } else {
            challenges.forEach(challenge => {
                const li = document.createElement('li');
                li.innerHTML = `
                <span>${challenge.name}</span>
                <span class="challenge-points">+${challenge.points}pts</span>
                `;
                challengeList.appendChild(li);
            });
        }

        popup.style.display = 'flex';
    }

    getDateForRange(range, index) {
        const now = new Date();
        const date = new Date(now);

        switch (range) {
            case 'week':
                date.setDate(date.getDate() - (6 - index));
                return date;
            case 'month':
                date.setDate(date.getDate() - (29 - index));
                return date;
            case 'year':
                date.setMonth(date.getMonth() - (11 - index));
                return date;
            default:
                return now;
        }
    }

    formatPopupDate(date, range) {
        switch (range) {
            case 'week':
                return date.toLocaleDateString('en-US', {weekday: 'long', month: 'short', day: 'numeric'});
            case 'month':
                return date.toLocaleDateString('en-US', {month: 'short', day: 'numeric'});
            case 'year':
                return date.toLocaleDateString('en-US', {year: 'numeric', month: 'long'});
            default:
                return date.toLocaleDateString();
        }
    }

    setupEventListeners() {
        this.setupPopupCloseListeners();
        this.setupTimeFilterListeners();
        this.setupViewOptionListeners();
        this.setupTimelineChartClickListener();
    }

    setupPopupCloseListeners() {
        document.querySelector('.close-popup').addEventListener('click', () => {
            document.getElementById('challengeDetailsPopup').style.display = 'none';
        });

        document.getElementById('challengeDetailsPopup').addEventListener('click', (e) => {
            if (e.target === e.currentTarget) {
                e.currentTarget.style.display = 'none';
            }
        });
    }

    setupTimeFilterListeners() {
        document.querySelectorAll('.time-filter').forEach(button => {
            button.addEventListener('click', async () => {
                document.querySelectorAll('.time-filter').forEach(btn => btn.classList.remove('active'));
                button.classList.add('active');

                const range = button.dataset.range;
                const viewType = document.querySelector('.view-option.active').dataset.type;

                await this.updateTimelineData(range, viewType);
            });
        });
    }

    setupViewOptionListeners() {
        document.querySelectorAll('.view-option').forEach(button => {
            button.addEventListener('click', async () => {
                document.querySelectorAll('.view-option').forEach(btn => btn.classList.remove('active'));
                button.classList.add('active');

                const range = document.querySelector('.time-filter.active').dataset.range;
                const viewType = button.dataset.type;

                await this.updateTimelineData(range, viewType);
            });
        });
    }

    async updateTimelineData(range, viewType) {
        const data = await apiClient.get(`../backend/dashboard.php?type=timeline&range=${range}&view=${viewType}`);
        if (data?.success) {
            this.timelineChart.data.labels = data.data.labels;
            this.timelineChart.data.datasets[0].data = data.data.points;
            this.timelineChart.data.datasets[1].data = data.data.challenges;
            this.timelineChart.update();
        }
    }

    setupTimelineChartClickListener() {
        this.timelineChart.options.onClick = async (e, elements) => {
            if (elements.length > 0) {
                const element = elements[0];
                const index = element.index;
                const range = document.querySelector('.time-filter.active').dataset.range;

                const data = await apiClient.get(`../backend/dashboard.php?type=timeline&range=${range}`);
                if (data?.success) {
                    this.showChallengeDetails(range, index, data.data.details[index]);
                }
            }
        };
    }

    updateActiveChallenge(challengeData) {
        const noChallengeElement = document.getElementById('no-active-challenge');
        const detailsElement = document.getElementById('active-challenge-details');

        if (!challengeData?.id) {
            noChallengeElement.style.display = 'block';
            detailsElement.style.display = 'none';
            this.clearTimeSpentInterval();
            return;
        }

        noChallengeElement.style.display = 'none';
        detailsElement.style.display = 'block';

        this.renderActiveChallengeDetails(challengeData);
        this.setupActiveChallengeEventListeners(challengeData.id);
    }

    clearTimeSpentInterval() {
        if (this.timeSpentInterval) {
            clearInterval(this.timeSpentInterval);
            this.timeSpentInterval = null;
        }
    }

    renderActiveChallengeDetails(challengeData) {
        document.getElementById('active-challenge-name').textContent = challengeData.name;
        document.getElementById('active-challenge-category').textContent = challengeData.category;
        document.getElementById('active-challenge-difficulty').textContent = challengeData.difficulty;
        document.getElementById('active-challenge-points').textContent = challengeData.points;
        document.getElementById('active-challenge-started').textContent = this.formatTimeAgo(challengeData.started_at);

        if (challengeData.elapsedSeconds !== undefined) {
            this.updateTimeSpentDisplay(challengeData.elapsedSeconds);
            this.startTimeSpentCounter(challengeData.elapsedSeconds);
        }
    }

    updateTimeSpentDisplay(totalSeconds) {
        document.getElementById('active-challenge-time-spent').textContent =
            this.formatTimeSpent(totalSeconds);
    }

    formatTimeSpent(totalSeconds) {
        const hours = Math.floor(totalSeconds / 3600);
        const minutes = Math.floor((totalSeconds % 3600) / 60);
        const seconds = totalSeconds % 60;

        return [
            hours > 0 ? `${hours}h` : '',
            minutes > 0 ? `${minutes}m` : '',
            `${seconds}s`
        ].filter(Boolean).join(' ');
    }

    startTimeSpentCounter(initialSeconds) {
        this.clearTimeSpentInterval();
        let currentSeconds = initialSeconds;

        this.timeSpentInterval = setInterval(() => {
            currentSeconds++;
            this.updateTimeSpentDisplay(currentSeconds);
        }, 1000);
    }

    setupActiveChallengeEventListeners(challengeId) {
        document.getElementById('view-challenge-btn').onclick = () => {
            window.location.href = `/challenge?id=${challengeId}`;
        };

        document.getElementById('cancel-challenge-btn').onclick = async () => {
            if (confirm('Are you sure you want to cancel this challenge? Your progress will be lost.')) {
                try {
                    const result = await apiClient.post('../backend/challenge.php', {
                        action: 'cancel',
                        challenge_id: challengeId
                    });

                    if (result?.success) {
                        this.updateActiveChallenge(null);
                    }
                } catch (error) {
                    console.error('Error canceling challenge:', error);
                    messageManager.showError('Error canceling challenge');
                }
            }
        };
    }

    formatTimeAgo(dateString) {
        if (!dateString) return '-';
        const date = new Date(dateString);
        const now = new Date();
        const diffInSeconds = Math.floor((now - date) / 1000);

        if (diffInSeconds < 60) return `${diffInSeconds} seconds ago`;
        if (diffInSeconds < 3600) return `${Math.floor(diffInSeconds / 60)} minutes ago`;
        if (diffInSeconds < 86400) return `${Math.floor(diffInSeconds / 3600)} hours ago`;
        return `${Math.floor(diffInSeconds / 86400)} days ago`;
    }
}

const dashboard = new Dashboard();
dashboard.init();
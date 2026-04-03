$(document).ready(function () {
    var socket = io.connect("http://" + document.domain + ":" + location.port + "/test");
    var recentFlows = [];
    var priorityFlows = [];
    var latestIps = [];
    var liveUpdatesPaused = false;
    var priorityOnly = false;
    var bufferedCount = 0;
    var maxRows = 40;
    var maxStoredRows = 200;
    var maxPriorityRows = 12;

    function normalizeText(value) {
        return String(value || "")
            .normalize("NFD")
            .replace(/[\u0300-\u036f]/g, "")
            .toLowerCase()
            .trim();
    }

    function riskRank(risk) {
        var normalized = normalizeText(risk);
        if (normalized.indexOf("rat cao") >= 0) {
            return 4;
        }
        if (normalized.indexOf("cao") >= 0) {
            return 3;
        }
        if (normalized.indexOf("trung binh") >= 0) {
            return 2;
        }
        if (normalized.indexOf("thap") >= 0 && normalized.indexOf("rat thap") === -1) {
            return 1;
        }
        return 0;
    }

    function riskClass(risk) {
        var rank = riskRank(risk);
        if (rank === 4) {
            return "risk-very-high";
        }
        if (rank === 3) {
            return "risk-high";
        }
        if (rank === 2) {
            return "risk-medium";
        }
        if (rank === 1) {
            return "risk-low";
        }
        return "risk-minimal";
    }

    function probabilityNumber(value) {
        var parsed = Number(value);
        if (Number.isNaN(parsed)) {
            return 0;
        }
        return parsed;
    }

    function probabilityLabel(value) {
        var parsed = Number(value);
        if (Number.isNaN(parsed)) {
            return value;
        }
        return (parsed * 100).toFixed(1) + "%";
    }

    function isBenignPrediction(prediction) {
        return normalizeText(prediction) === "luu luong hop le";
    }

    function isPriorityFlow(flow) {
        return riskRank(flow.risk) >= 2;
    }

    function isHighRiskFlow(flow) {
        return riskRank(flow.risk) >= 3;
    }

    function displayValue(value, fallback) {
        if (value === null || value === undefined || value === "" || normalizeText(value) === "none") {
            return fallback;
        }
        return value;
    }

    function sortPriorityFlows() {
        priorityFlows.sort(function (left, right) {
            var rankDiff = riskRank(right.risk) - riskRank(left.risk);
            if (rankDiff !== 0) {
                return rankDiff;
            }

            var probabilityDiff = probabilityNumber(right.probability) - probabilityNumber(left.probability);
            if (probabilityDiff !== 0) {
                return probabilityDiff;
            }

            return Number(right.id || 0) - Number(left.id || 0);
        });
    }

    function updatePriorityFlows(flow) {
        if (!isPriorityFlow(flow)) {
            return;
        }

        priorityFlows = priorityFlows.filter(function (item) {
            return item.id !== flow.id;
        });

        priorityFlows.unshift(flow);
        sortPriorityFlows();

        if (priorityFlows.length > maxPriorityRows) {
            priorityFlows = priorityFlows.slice(0, maxPriorityRows);
        }
    }

    function visibleFlows() {
        var flows = recentFlows.slice();
        if (priorityOnly) {
            flows = flows.filter(isPriorityFlow);
        }
        return flows.slice(0, maxRows);
    }

    function tableEmptyMessage() {
        if (priorityOnly) {
            return "Chưa có bản ghi ở mức rủi ro cần ưu tiên trong khung hiển thị hiện tại.";
        }
        return "Chưa có dữ liệu lưu lượng trực tiếp. Hệ thống sẽ tự động hiển thị bản ghi mới ngay khi phát sinh kết nối mạng.";
    }

    function renderMainTable() {
        var flows = visibleFlows();
        var tableBody = "";

        if (!flows.length) {
            tableBody = '<tr><td colspan="14" class="empty-state">' + tableEmptyMessage() + "</td></tr>";
        } else {
            for (var i = 0; i < flows.length; i++) {
                tableBody += renderMainRow(flows[i]);
            }
        }

        $("#details tbody").html(tableBody);
    }

    function renderMainRow(flow) {
        var appName = displayValue(flow.appName, "Chưa xác định");
        var pidLabel = displayValue(flow.pid, "Chưa xác định");
        var predictionClass = isBenignPrediction(flow.prediction) ? "is-benign" : "is-alert";
        var priorityBadge = isPriorityFlow(flow) ? ' flow-row-priority' : "";
        var row = "";

        row += '<tr class="' + priorityBadge.trim() + '">';
        row += "<td><strong>#" + flow.id + "</strong></td>";
        row += "<td>" + flow.src + "</td>";
        row += "<td>" + flow.srcPort + "</td>";
        row += "<td>" + flow.dst + "</td>";
        row += "<td>" + flow.dstPort + "</td>";
        row += "<td>" + flow.protocol + "</td>";
        row += "<td>" + flow.start + "</td>";
        row += "<td>" + flow.lastSeen + "</td>";
        row += "<td>" + appName + '<span class="cell-secondary">PID ' + pidLabel + "</span></td>";
        row += "<td>" + pidLabel + "</td>";
        row += '<td><span class="prediction-pill ' + predictionClass + '">' + flow.prediction + "</span></td>";
        row += "<td>" + probabilityLabel(flow.probability) + "</td>";
        row += '<td><span class="risk-pill ' + riskClass(flow.risk) + '">' + flow.risk + "</span></td>";
        row += '<td><a class="action-link" href="/flow-detail?flow_id=' + flow.id + '">Phân tích</a></td>';
        row += "</tr>";

        return row;
    }

    function renderPriorityTable() {
        var flows = priorityFlows.slice(0, maxPriorityRows);
        var tableBody = "";

        if (!flows.length) {
            tableBody = '<tr><td colspan="7" class="empty-state">Chưa có bản ghi cần ưu tiên phân tích. Các bản ghi từ mức Trung bình trở lên sẽ được giữ lại tại đây.</td></tr>';
        } else {
            for (var i = 0; i < flows.length; i++) {
                tableBody += renderPriorityRow(flows[i]);
            }
        }

        $("#priority-details tbody").html(tableBody);
        $("#priority-count").text(flows.length);
    }

    function renderPriorityRow(flow) {
        var predictionClass = isBenignPrediction(flow.prediction) ? "is-benign" : "is-alert";
        var row = "";

        row += '<tr class="flow-row-priority">';
        row += "<td><strong>#" + flow.id + "</strong></td>";
        row += "<td>" + flow.src + "</td>";
        row += "<td>" + flow.dst + "</td>";
        row += '<td><span class="prediction-pill ' + predictionClass + '">' + flow.prediction + "</span></td>";
        row += "<td>" + probabilityLabel(flow.probability) + "</td>";
        row += '<td><span class="risk-pill ' + riskClass(flow.risk) + '">' + flow.risk + "</span></td>";
        row += '<td><a class="action-link" href="/flow-detail?flow_id=' + flow.id + '">Phân tích</a></td>';
        row += "</tr>";

        return row;
    }

    function renderStats(ips) {
        var flows = visibleFlows();
        var highRisk = flows.filter(isHighRiskFlow).length;
        var benign = flows.filter(function (flow) {
            return isBenignPrediction(flow.prediction);
        }).length;

        $("#stat-total").text(flows.length);
        $("#stat-high-risk").text(highRisk);
        $("#stat-benign").text(benign);
        $("#stat-sources").text((ips || []).length);
    }

    function renderChart(ips) {
        var chartIps = ips || [];
        myChart.data.labels = [];
        myChart.data.datasets[0].data = [];

        for (var i = 0; i < chartIps.length; i++) {
            myChart.data.labels.push(chartIps[i].SourceIP);
            myChart.data.datasets[0].data.push(chartIps[i].count);
        }

        myChart.update();
    }

    function renderControls() {
        var pauseButton = $("#toggle-live");
        var priorityButton = $("#toggle-priority");
        var statusText = $("#table-status");

        pauseButton.toggleClass("is-active", liveUpdatesPaused);
        priorityButton.toggleClass("is-active", priorityOnly);

        if (liveUpdatesPaused) {
            pauseButton.text("Tiếp tục cập nhật");
            statusText.text("Bảng chính đang được giữ nguyên để thao tác. Có " + bufferedCount + " bản ghi mới chờ hiển thị.");
        } else if (priorityOnly) {
            pauseButton.text("Tạm dừng cập nhật bảng");
            statusText.text("Đang lọc riêng các bản ghi cần ưu tiên phân tích để thao tác nhanh hơn.");
        } else {
            pauseButton.text("Tạm dừng cập nhật bảng");
            statusText.text("Bảng đang tự động cập nhật theo thời gian thực. Bạn có thể tạm dừng khi cần phân tích chi tiết.");
        }

        priorityButton.text(priorityOnly ? "Hiện toàn bộ bản ghi" : "Chỉ xem bản ghi cần ưu tiên");
    }

    function refreshDashboard() {
        renderMainTable();
        renderStats(latestIps);
        renderChart(latestIps);
        renderControls();
    }

    $("#toggle-live").on("click", function () {
        liveUpdatesPaused = !liveUpdatesPaused;

        if (!liveUpdatesPaused) {
            bufferedCount = 0;
            refreshDashboard();
        } else {
            renderControls();
        }
    });

    $("#toggle-priority").on("click", function () {
        priorityOnly = !priorityOnly;
        if (!liveUpdatesPaused) {
            refreshDashboard();
        } else {
            renderControls();
        }
    });

    var ctx = document.getElementById("myChart");
    var myChart = new Chart(ctx, {
        type: "bar",
        data: {
            labels: [],
            datasets: [{
                data: [],
                backgroundColor: "rgba(15, 108, 189, 0.78)",
                borderColor: "rgba(16, 42, 67, 1)",
                borderWidth: 1.5,
                hoverBackgroundColor: "rgba(183, 121, 31, 0.82)"
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            legend: {
                display: false
            },
            scales: {
                yAxes: [{
                    ticks: {
                        beginAtZero: true,
                        fontColor: "#486581"
                    },
                    gridLines: {
                        color: "rgba(72, 101, 129, 0.14)"
                    }
                }],
                xAxes: [{
                    ticks: {
                        fontColor: "#486581"
                    },
                    gridLines: {
                        display: false
                    }
                }]
            }
        }
    });

    socket.on("newresult", function (msg) {
        var result = msg.result || [];
        var flow = {
            id: result[0],
            src: result[1],
            srcPort: result[2],
            dst: result[3],
            dstPort: result[4],
            protocol: result[5],
            start: result[6],
            lastSeen: result[7],
            appName: result[8],
            pid: result[9],
            prediction: result[10],
            probability: result[11],
            risk: result[12]
        };

        latestIps = msg.ips || [];

        recentFlows.unshift(flow);
        if (recentFlows.length > maxStoredRows) {
            recentFlows = recentFlows.slice(0, maxStoredRows);
        }

        updatePriorityFlows(flow);
        renderPriorityTable();

        if (liveUpdatesPaused) {
            bufferedCount += 1;
            renderControls();
            return;
        }

        refreshDashboard();
    });

    renderPriorityTable();
    renderControls();
    renderMainTable();
});

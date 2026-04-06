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
    var apiLimit = 200;

    function normalizeText(value) {
        return String(value || "")
            .normalize("NFD")
            .replace(/[\u0300-\u036f]/g, "")
            .toLowerCase()
            .trim();
    }

    function currentFilters() {
        return {
            q: $.trim($("#filter-query").val() || ""),
            risk: $("#filter-risk").val() || "",
            prediction: $("#filter-prediction").val() || "",
            protocol: $("#filter-protocol").val() || ""
        };
    }

    function hasActiveFilters() {
        var filters = currentFilters();
        return Boolean(filters.q || filters.risk || filters.prediction || filters.protocol);
    }

    function buildApiQuery(includeLimit) {
        var filters = currentFilters();
        var params = new URLSearchParams();

        if (filters.q) {
            params.set("q", filters.q);
        }
        if (filters.risk) {
            params.set("risk", filters.risk);
        }
        if (filters.prediction) {
            params.set("prediction", filters.prediction);
        }
        if (filters.protocol) {
            params.set("protocol", filters.protocol);
        }
        if (includeLimit) {
            params.set("limit", apiLimit);
        }

        return params.toString();
    }

    function riskRank(risk) {
        var normalized = normalizeText(risk);
        if (normalized.indexOf("very high") >= 0 || normalized.indexOf("rat cao") >= 0) {
            return 4;
        }
        if (normalized === "high" || normalized.indexOf("cao") >= 0) {
            return 3;
        }
        if (normalized.indexOf("medium") >= 0 || normalized.indexOf("trung binh") >= 0) {
            return 2;
        }
        if ((normalized === "low" || normalized.indexOf("thap") >= 0) && normalized.indexOf("rat thap") === -1) {
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
        var normalized = normalizeText(prediction);
        return normalized === "luu luong hop le" || normalized === "benign";
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

    function normalizeFlow(flow) {
        return {
            id: flow.id,
            src: flow.src,
            srcDisplay: flow.srcDisplay || flow.src,
            srcPort: flow.srcPort,
            dst: flow.dst,
            dstDisplay: flow.dstDisplay || flow.dst,
            dstPort: flow.dstPort,
            protocol: flow.protocol,
            start: flow.start,
            lastSeen: flow.lastSeen,
            appName: flow.appName,
            pid: flow.pid,
            prediction: flow.prediction,
            probability: flow.probability,
            risk: flow.risk
        };
    }

    function flowMatchesFilters(flow) {
        var filters = currentFilters();
        var searchMatch = true;
        var normalizedQuery = normalizeText(filters.q);

        if (normalizedQuery) {
            searchMatch = [
                flow.src,
                flow.dst,
                flow.srcPort,
                flow.dstPort,
                flow.protocol,
                flow.appName,
                flow.pid,
                flow.prediction,
                flow.risk
            ].some(function (value) {
                return normalizeText(value).indexOf(normalizedQuery) >= 0;
            });
        }

        if (!searchMatch) {
            return false;
        }
        if (filters.risk && flow.risk !== filters.risk) {
            return false;
        }
        if (filters.prediction && flow.prediction !== filters.prediction) {
            return false;
        }
        if (filters.protocol && normalizeText(flow.protocol) !== normalizeText(filters.protocol)) {
            return false;
        }
        return true;
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

    function rebuildPriorityFlows() {
        priorityFlows = recentFlows.filter(isPriorityFlow);
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
        return "Chưa có dữ liệu lưu lượng phù hợp với bộ lọc hiện tại.";
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
        var priorityBadge = isPriorityFlow(flow) ? " flow-row-priority" : "";
        var row = "";

        row += '<tr class="' + priorityBadge.trim() + '">';
        row += "<td><strong>#" + flow.id + "</strong></td>";
        row += "<td>" + (flow.srcDisplay || flow.src) + "</td>";
        row += "<td>" + flow.srcPort + "</td>";
        row += "<td>" + (flow.dstDisplay || flow.dst) + "</td>";
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
        row += "<td>" + (flow.srcDisplay || flow.src) + "</td>";
        row += "<td>" + (flow.dstDisplay || flow.dst) + "</td>";
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
            statusText.text("Bảng chính đang được giữ nguyên để thao tác. Có " + bufferedCount + " alert mới chờ hiển thị.");
        } else if (hasActiveFilters()) {
            pauseButton.text("Tạm dừng cập nhật bảng");
            statusText.text("Dữ liệu lịch sử đang được đọc từ SQLite theo bộ lọc hiện tại.");
        } else if (priorityOnly) {
            pauseButton.text("Tạm dừng cập nhật bảng");
            statusText.text("Đang lọc riêng các bản ghi cần ưu tiên phân tích để thao tác nhanh hơn.");
        } else {
            pauseButton.text("Tạm dừng cập nhật bảng");
            statusText.text("Bảng đang tự động cập nhật theo thời gian thực. Lịch sử alert được lưu trong SQLite để tìm kiếm và export.");
        }

        priorityButton.text(priorityOnly ? "Hiện toàn bộ bản ghi" : "Chỉ xem bản ghi cần ưu tiên");
    }

    function refreshDashboard() {
        renderMainTable();
        renderPriorityTable();
        renderStats(latestIps);
        renderChart(latestIps);
        renderControls();
    }

    function upsertFlow(flow) {
        recentFlows = recentFlows.filter(function (item) {
            return item.id !== flow.id;
        });
        recentFlows.unshift(flow);
        if (recentFlows.length > maxStoredRows) {
            recentFlows = recentFlows.slice(0, maxStoredRows);
        }
        rebuildPriorityFlows();
    }

    function loadHistory() {
        var query = buildApiQuery(true);
        var url = "/api/alerts";
        if (query) {
            url += "?" + query;
        }

        $.getJSON(url)
            .done(function (response) {
                recentFlows = (response.items || []).map(normalizeFlow);
                latestIps = response.top_sources || [];
                rebuildPriorityFlows();
                bufferedCount = 0;
                refreshDashboard();
            })
            .fail(function () {
                $("#table-status").text("Không thể tải lịch sử alert từ database.");
            });
    }

    function exportHistory() {
        var query = buildApiQuery(false);
        var url = "/api/alerts/export";
        if (query) {
            url += "?" + query;
        }
        window.open(url, "_blank");
    }

    $("#toggle-live").on("click", function () {
        liveUpdatesPaused = !liveUpdatesPaused;
        if (!liveUpdatesPaused) {
            loadHistory();
            return;
        }
        renderControls();
    });

    $("#toggle-priority").on("click", function () {
        priorityOnly = !priorityOnly;
        refreshDashboard();
    });

    $("#apply-filters").on("click", function () {
        loadHistory();
    });

    $("#reset-filters").on("click", function () {
        $("#filter-query").val("");
        $("#filter-risk").val("");
        $("#filter-prediction").val("");
        $("#filter-protocol").val("");
        loadHistory();
    });

    $("#export-filters").on("click", function () {
        exportHistory();
    });

    $("#filter-query").on("keydown", function (event) {
        if (event.key === "Enter") {
            event.preventDefault();
            loadHistory();
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
        var flow = normalizeFlow(msg.result || {});

        if (!hasActiveFilters()) {
            latestIps = msg.ips || [];
        }

        if (hasActiveFilters() && !flowMatchesFilters(flow)) {
            if (liveUpdatesPaused) {
                bufferedCount += 1;
            }
            renderControls();
            return;
        }

        upsertFlow(flow);

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
    loadHistory();
});

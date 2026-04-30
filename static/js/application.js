$(document).ready(function () {
    var socket = io("/test");
    var recentFlows = [];
    var priorityFlows = [];
    var latestIps = [];
    var runtimeState = null;
    var liveUpdatesPaused = false;
    var priorityOnly = false;
    var bufferedCount = 0;
    var socketConnected = false;
    var runtimePollHandle = null;
    var filterInputDebounceHandle = null;
    var maxRows = 40;
    var maxStoredRows = 200;
    var maxPriorityRows = 12;
    var apiLimit = 200;
    var nextDisplayId = 1;
    var displayIdByKey = {};

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
        if (normalized === "high" || normalized === "cao") {
            return 3;
        }
        if (normalized.indexOf("medium") >= 0 || normalized.indexOf("trung binh") >= 0) {
            return 2;
        }
        if (normalized === "low" || normalized === "thap") {
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
        if (value === null || value === undefined || value === "") {
            return 0;
        }
        var parsed = Number(value);
        if (Number.isNaN(parsed)) {
            return 0;
        }
        return parsed;
    }

    function probabilityLabel(value) {
        if (value === null || value === undefined || value === "") {
            return "-";
        }
        var parsed = Number(value);
        if (Number.isNaN(parsed)) {
            return value || "-";
        }
        var percentage = Math.max(0, parsed * 100);
        if (percentage >= 100) {
            return "99.99%";
        }
        return percentage.toFixed(2) + "%";
    }

    function isBenignPrediction(prediction) {
        var normalized = normalizeText(prediction);
        return normalized === "luu luong hop le" || normalized === "benign";
    }

    function isFloodAttackPrediction(prediction) {
        var normalized = normalizeText(prediction);
        return normalized === "tan cong dos" || normalized === "dos" || normalized === "tan cong ddos" || normalized === "ddos";
    }

    function isPriorityFlow(flow) {
        if (flow && flow.isProvisional) {
            return false;
        }
        if (flow && typeof flow.isPriority === "boolean") {
            return flow.isPriority;
        }
        if (isFloodAttackPrediction(flow.prediction)) {
            return riskRank(flow.risk) >= 3;
        }
        return !isBenignPrediction(flow.prediction) || riskRank(flow.risk) > 2;
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

    function analysisUrl(flow) {
        if (flow.isProvisional && flow.flowKey) {
            return "/flow-detail?flow_key=" + encodeURIComponent(flow.flowKey);
        }
        return "/flow-detail?flow_id=" + encodeURIComponent(flow.id);
    }

    function displayKeyForFlow(flow) {
        if (flow.flowKey) {
            return "flow:" + flow.flowKey;
        }
        return "id:" + String(flow.id || "");
    }

    function persistedDisplayId(flow) {
        var parsedId = Number(flow.id);
        if (flow.isProvisional || Number.isNaN(parsedId) || parsedId <= 0) {
            return null;
        }
        return parsedId;
    }

    function assignDisplayId(flow) {
        var persistedId = persistedDisplayId(flow);
        var displayKey = displayKeyForFlow(flow);

        if (persistedId !== null) {
            flow.displayId = persistedId;
            displayIdByKey["id:" + String(flow.id)] = persistedId;
            if (flow.flowKey) {
                displayIdByKey["flow:" + flow.flowKey] = persistedId;
            }
            if (persistedId >= nextDisplayId) {
                nextDisplayId = persistedId + 1;
            }
            return flow;
        }

        if (displayIdByKey[displayKey]) {
            flow.displayId = displayIdByKey[displayKey];
            return flow;
        }

        flow.displayId = null;
        return flow;
    }

    function normalizeFlow(flow) {
        var parsedId = Number(flow.id);
        var serviceHints = Array.isArray(flow.serviceHints) ? flow.serviceHints.slice() : [];
        return {
            id: flow.id,
            flowKey: flow.flowKey || "",
            displayId: Number.isNaN(parsedId) ? null : parsedId,
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
            serviceHints: serviceHints,
            probability: flow.probability,
            risk: flow.risk,
            isPriority: Boolean(flow.isPriority),
            isProvisional: Boolean(flow.isProvisional)
        };
    }

    function predictionMatchesFilter(flow, selectedPrediction) {
        if (!selectedPrediction) {
            return true;
        }

        if (flow.prediction === selectedPrediction) {
            return true;
        }

        return (flow.serviceHints || []).some(function (hint) {
            return hint === selectedPrediction;
        });
    }

    function flowMatchesFilters(flow) {
        var filters = currentFilters();
        var normalizedQuery = normalizeText(filters.q);
        var searchMatch = true;

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
                (flow.serviceHints || []).join(", "),
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
        if (!predictionMatchesFilter(flow, filters.prediction)) {
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

            var rightId = Number(right.id);
            var leftId = Number(left.id);
            if (!Number.isNaN(rightId) && !Number.isNaN(leftId)) {
                return rightId - leftId;
            }
            return normalizeText(String(right.id || "")).localeCompare(normalizeText(String(left.id || "")));
        });
    }

    function rebuildPriorityFlows() {
        priorityFlows = recentFlows.filter(isPriorityFlow);
        sortPriorityFlows();
        if (priorityFlows.length > maxPriorityRows) {
            priorityFlows = priorityFlows.slice(0, maxPriorityRows);
        }
    }

    function computeTopSources(flows, limit) {
        var counts = {};
        var entries = [];
        var maxItems = limit || 10;

        for (var index = 0; index < flows.length; index += 1) {
            var sourceIp = flows[index].src;
            if (!sourceIp) {
                continue;
            }
            counts[sourceIp] = (counts[sourceIp] || 0) + 1;
        }

        Object.keys(counts).forEach(function (sourceIp) {
            entries.push({
                SourceIP: sourceIp,
                count: counts[sourceIp]
            });
        });

        entries.sort(function (left, right) {
            var countDiff = right.count - left.count;
            if (countDiff !== 0) {
                return countDiff;
            }
            return normalizeText(left.SourceIP).localeCompare(normalizeText(right.SourceIP));
        });

        return entries.slice(0, maxItems);
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
            return "Chưa có bản ghi ưu tiên trong khung hiển thị hiện tại.";
        }
        return "Chưa có dữ liệu lưu lượng phù hợp với bộ lọc hiện tại.";
    }

    function renderMainRow(flow) {
        var appName = displayValue(flow.appName, "Chưa xác định");
        var pidLabel = displayValue(flow.pid, "Chưa xác định");
        var predictionClass = isBenignPrediction(flow.prediction) ? "is-benign" : "is-alert";
        var primaryPrediction = "";
        var rowClass = isPriorityFlow(flow) ? "flow-row-priority" : "";
        var row = "";

        row += '<tr class="' + rowClass + '">';
        row += "<td><strong>#" + displayValue(flow.displayId, "-") + "</strong></td>";
        row += "<td>" + (flow.srcDisplay || flow.src) + "</td>";
        row += "<td>" + displayValue(flow.srcPort, "-") + "</td>";
        row += "<td>" + (flow.dstDisplay || flow.dst) + "</td>";
        row += "<td>" + displayValue(flow.dstPort, "-") + "</td>";
        row += "<td>" + displayValue(flow.protocol, "-") + "</td>";
        row += "<td>" + displayValue(flow.start, "-") + "</td>";
        row += "<td>" + displayValue(flow.lastSeen, "-") + "</td>";
        row += "<td>" + appName + '<span class="cell-secondary">PID ' + pidLabel + "</span></td>";
        row += "<td>" + pidLabel + "</td>";
        row += '<td><span class="prediction-pill ' + predictionClass + '">' + displayValue(flow.prediction, "-") + "</span>";
        if (primaryPrediction && primaryPrediction !== flow.prediction) {
            row += '<span class="cell-secondary">Nhãn gốc: ' + primaryPrediction + "</span>";
        }
        row += "</td>";
        row += "<td>" + probabilityLabel(flow.probability) + "</td>";
        row += '<td><span class="risk-pill ' + riskClass(flow.risk) + '">' + displayValue(flow.risk, "-") + "</span></td>";
        row += '<td><a class="action-link" href="' + analysisUrl(flow) + '">Phân tích</a></td>';
        row += "</tr>";

        return row;
    }

    function renderMainTable() {
        var flows = visibleFlows();
        var tableBody = "";

        if (!flows.length) {
            tableBody = '<tr><td colspan="14" class="empty-state">' + tableEmptyMessage() + "</td></tr>";
        } else {
            for (var index = 0; index < flows.length; index += 1) {
                tableBody += renderMainRow(flows[index]);
            }
        }

        $("#details tbody").html(tableBody);
    }

    function renderPriorityRow(flow) {
        var predictionClass = isBenignPrediction(flow.prediction) ? "is-benign" : "is-alert";
        var primaryPrediction = "";
        var row = "";

        row += '<tr class="flow-row-priority">';
        row += "<td><strong>" + displayValue(flow.displayId, "-") + "</strong></td>";
        row += "<td>" + (flow.srcDisplay || flow.src) + "</td>";
        row += "<td>" + (flow.dstDisplay || flow.dst) + "</td>";
        row += '<td><span class="prediction-pill ' + predictionClass + '">' + flow.prediction + "</span>";
        if (primaryPrediction && primaryPrediction !== flow.prediction) {
            row += '<span class="cell-secondary">Nhãn gốc: ' + primaryPrediction + "</span>";
        }
        row += "</td>";
        row += "<td>" + probabilityLabel(flow.probability) + "</td>";
        row += '<td><span class="risk-pill ' + riskClass(flow.risk) + '">' + flow.risk + "</span></td>";
        row += '<td><a class="action-link" href="' + analysisUrl(flow) + '">Phân tích</a></td>';
        row += "</tr>";

        return row;
    }

    function renderPriorityTable() {
        var flows = priorityFlows.slice(0, maxPriorityRows);
        var tableBody = "";

        if (!flows.length) {
            tableBody = '<tr><td colspan="7" class="empty-state">Chưa có bản ghi cần ưu tiên phân tích.</td></tr>';
        } else {
            for (var index = 0; index < flows.length; index += 1) {
                tableBody += renderPriorityRow(flows[index]);
            }
        }

        $("#priority-details tbody").html(tableBody);
        $("#priority-count").text(flows.length);
    }

    function renderStats(ips) {
        var flows = visibleFlows();
        var highRisk = flows.filter(isHighRiskFlow).length;
        var benign = flows.filter(function (flow) {
            return isBenignPrediction(flow.prediction);
        }).length;
        var sourceCount = runtimeState && runtimeState.known_sources !== undefined
            ? runtimeState.known_sources
            : (ips || []).length;

        $("#stat-total").text(flows.length);
        $("#stat-high-risk").text(highRisk);
        $("#stat-benign").text(benign);
        $("#stat-sources").text(sourceCount);
    }

    function renderChart(ips) {
        var chartIps = ips || [];
        chart.data.labels = [];
        chart.data.datasets[0].data = [];

        for (var index = 0; index < chartIps.length; index += 1) {
            chart.data.labels.push(chartIps[index].SourceIP);
            chart.data.datasets[0].data.push(chartIps[index].count);
        }

        chart.update();
    }

    function formatUptime(totalSeconds) {
        var seconds = Math.max(Number(totalSeconds) || 0, 0);
        var days = Math.floor(seconds / 86400);
        var hours = Math.floor((seconds % 86400) / 3600);
        var minutes = Math.floor((seconds % 3600) / 60);
        var secs = seconds % 60;
        var parts = [];

        if (days) {
            parts.push(days + "d");
        }
        if (hours || days) {
            parts.push(hours + "h");
        }
        if (minutes || hours || days) {
            parts.push(minutes + "m");
        }
        parts.push(secs + "s");
        return parts.join(" ");
    }

    function setHeroStatus(text, state) {
        var dot = $("#hero-runtime-dot");
        $("#hero-runtime-text").text(text);
        dot.removeClass("is-warning is-danger");
        if (state === "warning") {
            dot.addClass("is-warning");
        } else if (state === "danger") {
            dot.addClass("is-danger");
        }
    }

    function renderRuntimeStatus() {
        if (!runtimeState) {
            $("#runtime-socket").text(socketConnected ? "Đã kết nối" : "Đang kiểm tra");
            $("#runtime-socket-note").text(socketConnected ? "Kênh realtime đã sẵn sàng." : "Đang chờ kết nối WebSocket.");
            return;
        }

        var captureHealthy = Boolean(runtimeState.capture_alive);
        var workerHealthy = Boolean(runtimeState.worker_alive);
        var queueSize = Number(runtimeState.queue_size || 0);
        var queueCapacity = Number(runtimeState.queue_capacity || 0);
        var queueRatio = queueCapacity > 0 ? queueSize / queueCapacity : 0;
        var queueNote = "Hàng đợi đang nhẹ.";
        var heroText = "Hệ thống đang ổn định và sẵn sàng ghi nhận alert mới.";
        var heroLevel = "ok";

        if (queueRatio >= 0.8) {
            queueNote = "Hàng đợi đang cao, nên kiểm tra tốc độ xử lý.";
            heroText = "Hàng đợi đang tăng cao, cần theo dõi thêm worker và capture.";
            heroLevel = "warning";
        }
        if (!captureHealthy || !workerHealthy) {
            heroText = "Một thành phần runtime đang gặp vấn đề, cần kiểm tra ngay.";
            heroLevel = "danger";
        }
        if (!socketConnected) {
            heroText = "WebSocket đang mất kết nối, giao diện sẽ không nhận alert realtime.";
            heroLevel = "warning";
        }
        if (Number(runtimeState.worker_errors || 0) > 0) {
            heroText = "Worker đã ghi nhận lỗi. Nên xem log để xác định nguyên nhân.";
            heroLevel = "danger";
        }

        setHeroStatus(heroText, heroLevel);

        $("#runtime-socket").text(socketConnected ? "Đã kết nối" : "Mất kết nối");
        $("#runtime-socket-note").text(socketConnected ? "Kênh realtime đang nhận alert mới." : "Dashboard đang chờ kết nối lại WebSocket.");

        $("#runtime-capture").text(captureHealthy ? "Đang chạy" : "Không hoạt động");
        $("#runtime-capture-note").text(
            captureHealthy
                ? "Capture đang theo dõi luồng mạng, timeout flow " + runtimeState.flow_timeout + "s."
                : "Capture thread không hoạt động. Kiểm tra quyền sniff và log runtime."
        );

        $("#runtime-worker").text(workerHealthy ? "Đang chạy" : "Không hoạt động");
        $("#runtime-worker-note").text(
            workerHealthy
                ? "Worker đang xử lý flow và ghi alert vào storage."
                : "Worker thread không hoạt động. Kiểm tra queue và log backend."
        );

        $("#runtime-queue").text(queueSize + " / " + queueCapacity);
        $("#runtime-queue-note").text(queueNote);

        $("#runtime-active-flows").text(runtimeState.active_flows || 0);
        $("#runtime-processed-flows").text(runtimeState.processed_flows || 0);
        $("#runtime-dropped-flows").text(runtimeState.dropped_flows || 0);
        $("#runtime-worker-errors").text(runtimeState.worker_errors || 0);
        $("#runtime-uptime").text(formatUptime(runtimeState.uptime_seconds));
        $("#runtime-geolocation").text("GeoIP: " + (runtimeState.geolocation_enabled ? "bật" : "tắt"));
        $("#runtime-explanations").text("LIME: " + (runtimeState.explanations_enabled ? "bật" : "tắt"));
    }

    function runtimeFailureMessage() {
        return "Không thể đọc trạng thái runtime.";
    }

    function renderControls() {
        var pauseButton = $("#toggle-live");
        var priorityButton = $("#toggle-priority");
        var statusText = $("#table-status");

        pauseButton.toggleClass("is-active", liveUpdatesPaused);
        priorityButton.toggleClass("is-active", priorityOnly);

        if (liveUpdatesPaused) {
            pauseButton.text("Tiếp tục cập nhật");
            statusText.text("Bảng chính đang được giữ nguyên để thao tác. Có " + bufferedCount + " bản cập nhật mới chờ hiển thị.");
        } else if (hasActiveFilters()) {
            pauseButton.text("Tạm dừng cập nhật bảng");
            statusText.text("Dữ liệu lịch sử đang được đọc từ SQLite theo bộ lọc hiện tại.");
        } else if (priorityOnly) {
            pauseButton.text("Tạm dừng cập nhật bảng");
            statusText.text("Đang lọc riêng các bản ghi cần ưu tiên phân tích.");
        } else {
            pauseButton.text("Tạm dừng cập nhật bảng");
            statusText.text("Bảng đang tự động cập nhật theo thời gian thực.");
        }

        priorityButton.text(priorityOnly ? "Hiện toàn bộ bản ghi" : "Chỉ xem bản ghi cần ưu tiên");
    }

    function refreshDashboard() {
        latestIps = computeTopSources(recentFlows, 10);
        renderMainTable();
        renderPriorityTable();
        renderStats(latestIps);
        renderChart(latestIps);
        renderControls();
        renderRuntimeStatus();
    }

    function upsertFlow(flow) {
        flow = assignDisplayId(flow);

        recentFlows = recentFlows.filter(function (item) {
            if (item.id === flow.id) {
                return false;
            }
            if (flow.flowKey && item.flowKey === flow.flowKey) {
                return false;
            }
            return true;
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
                displayIdByKey = {};
                nextDisplayId = 1;
                recentFlows = (response.items || []).map(function (item) {
                    return assignDisplayId(normalizeFlow(item));
                });
                rebuildPriorityFlows();
                bufferedCount = 0;
                refreshDashboard();
            })
            .fail(function () {
                $("#table-status").text("Không thể tải lịch sử alert từ database.");
            });
    }

    function scheduleHistoryReload() {
        if (filterInputDebounceHandle) {
            window.clearTimeout(filterInputDebounceHandle);
        }
        filterInputDebounceHandle = window.setTimeout(function () {
            loadHistory();
        }, 250);
    }

    function loadRuntimeStatus() {
        $.getJSON("/api/runtime-status")
            .done(function (response) {
                runtimeState = response || {};
                renderRuntimeStatus();
                renderStats(latestIps);
            })
            .fail(function () {
                runtimeState = null;
                $("#runtime-capture").text("Không rõ");
                $("#runtime-worker").text("Không rõ");
                $("#runtime-queue").text("Không rõ");
                $("#runtime-capture-note").text(runtimeFailureMessage());
                $("#runtime-worker-note").text(runtimeFailureMessage());
                $("#runtime-queue-note").text(runtimeFailureMessage());
                setHeroStatus(runtimeFailureMessage(), "warning");
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

    $("#reset-filters").on("click", function () {
        $("#filter-query").val("");
        $("#filter-risk").val("");
        $("#filter-prediction").val("");
        $("#filter-protocol").val("");
        if (filterInputDebounceHandle) {
            window.clearTimeout(filterInputDebounceHandle);
            filterInputDebounceHandle = null;
        }
        loadHistory();
    });

    $("#export-filters").on("click", function () {
        exportHistory();
    });

    $("#filter-risk, #filter-prediction, #filter-protocol").on("change", function () {
        loadHistory();
    });

    $("#filter-query").on("input", function () {
        scheduleHistoryReload();
    });

    $("#filter-query").on("keydown", function (event) {
        if (event.key === "Enter") {
            event.preventDefault();
            if (filterInputDebounceHandle) {
                window.clearTimeout(filterInputDebounceHandle);
                filterInputDebounceHandle = null;
            }
            loadHistory();
        }
    });

    var chart = new Chart(document.getElementById("myChart"), {
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

    socket.on("connect", function () {
        socketConnected = true;
        renderRuntimeStatus();
    });

    socket.on("disconnect", function () {
        socketConnected = false;
        renderRuntimeStatus();
    });

    socket.on("connect_error", function () {
        socketConnected = false;
        renderRuntimeStatus();
    });

    socket.on("newresult", function (msg) {
        var flow = normalizeFlow(msg.result || {});

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
    loadRuntimeStatus();
    runtimePollHandle = window.setInterval(loadRuntimeStatus, 5000);

    $(window).on("beforeunload", function () {
        if (filterInputDebounceHandle) {
            window.clearTimeout(filterInputDebounceHandle);
        }
        if (runtimePollHandle) {
            window.clearInterval(runtimePollHandle);
        }
    });
});

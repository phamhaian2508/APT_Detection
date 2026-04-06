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

    function visibleFlows() {
        var flows = recentFlows.slice();
        if (priorityOnly) {
            flows = flows.filter(isPriorityFlow);
        }
        return flows.slice(0, maxRows);
    }

    function tableEmptyMessage() {
        if (priorityOnly) {
            return "Chua co ban ghi uu tien trong khung hien thi hien tai.";
        }
        return "Chua co du lieu luu luong phu hop voi bo loc hien tai.";
    }

    function renderMainRow(flow) {
        var appName = displayValue(flow.appName, "Chua xac dinh");
        var pidLabel = displayValue(flow.pid, "Chua xac dinh");
        var predictionClass = isBenignPrediction(flow.prediction) ? "is-benign" : "is-alert";
        var rowClass = isPriorityFlow(flow) ? "flow-row-priority" : "";
        var row = "";

        row += '<tr class="' + rowClass + '">';
        row += "<td><strong>#" + displayValue(flow.id, "-") + "</strong></td>";
        row += "<td>" + (flow.srcDisplay || flow.src) + "</td>";
        row += "<td>" + displayValue(flow.srcPort, "-") + "</td>";
        row += "<td>" + (flow.dstDisplay || flow.dst) + "</td>";
        row += "<td>" + displayValue(flow.dstPort, "-") + "</td>";
        row += "<td>" + displayValue(flow.protocol, "-") + "</td>";
        row += "<td>" + displayValue(flow.start, "-") + "</td>";
        row += "<td>" + displayValue(flow.lastSeen, "-") + "</td>";
        row += "<td>" + appName + '<span class="cell-secondary">PID ' + pidLabel + "</span></td>";
        row += "<td>" + pidLabel + "</td>";
        row += '<td><span class="prediction-pill ' + predictionClass + '">' + displayValue(flow.prediction, "-") + "</span></td>";
        row += "<td>" + probabilityLabel(flow.probability) + "</td>";
        row += '<td><span class="risk-pill ' + riskClass(flow.risk) + '">' + displayValue(flow.risk, "-") + "</span></td>";
        row += '<td><a class="action-link" href="/flow-detail?flow_id=' + flow.id + '">Phan tich</a></td>';
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
        var row = "";

        row += '<tr class="flow-row-priority">';
        row += "<td><strong>" + flow.id + "</strong></td>";
        row += "<td>" + (flow.srcDisplay || flow.src) + "</td>";
        row += "<td>" + (flow.dstDisplay || flow.dst) + "</td>";
        row += '<td><span class="prediction-pill ' + predictionClass + '">' + flow.prediction + "</span></td>";
        row += "<td>" + probabilityLabel(flow.probability) + "</td>";
        row += '<td><span class="risk-pill ' + riskClass(flow.risk) + '">' + flow.risk + "</span></td>";
        row += '<td><a class="action-link" href="/flow-detail?flow_id=' + flow.id + '">Phan tich</a></td>';
        row += "</tr>";

        return row;
    }

    function renderPriorityTable() {
        var flows = priorityFlows.slice(0, maxPriorityRows);
        var tableBody = "";

        if (!flows.length) {
            tableBody = '<tr><td colspan="7" class="empty-state">Chua co ban ghi can uu tien phan tich.</td></tr>';
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
            $("#runtime-socket").text(socketConnected ? "Da ket noi" : "Dang kiem tra");
            $("#runtime-socket-note").text(socketConnected ? "Kenh realtime da san sang." : "Dang cho ket noi websocket.");
            return;
        }

        var captureHealthy = Boolean(runtimeState.capture_alive);
        var workerHealthy = Boolean(runtimeState.worker_alive);
        var queueSize = Number(runtimeState.queue_size || 0);
        var queueCapacity = Number(runtimeState.queue_capacity || 0);
        var queueRatio = queueCapacity > 0 ? queueSize / queueCapacity : 0;
        var queueNote = "Hang doi dang nhe.";
        var heroText = "He thong dang on dinh va san sang ghi nhan alert moi.";
        var heroLevel = "ok";

        if (queueRatio >= 0.8) {
            queueNote = "Hang doi dang cao, nen kiem tra toc do xu ly.";
            heroText = "Hang doi dang tang cao, can theo doi them worker va capture.";
            heroLevel = "warning";
        }
        if (!captureHealthy || !workerHealthy) {
            heroText = "Mot thanh phan runtime dang gap van de, can kiem tra ngay.";
            heroLevel = "danger";
        }
        if (!socketConnected) {
            heroText = "Websocket dang mat ket noi, giao dien se khong nhan alert realtime.";
            heroLevel = "warning";
        }
        if (Number(runtimeState.worker_errors || 0) > 0) {
            heroText = "Worker da ghi nhan loi. Nen xem log de xac dinh nguyen nhan.";
            heroLevel = "danger";
        }

        setHeroStatus(heroText, heroLevel);

        $("#runtime-socket").text(socketConnected ? "Da ket noi" : "Mat ket noi");
        $("#runtime-socket-note").text(socketConnected ? "Kenh realtime dang nhan alert moi." : "Dashboard dang cho ket noi lai websocket.");

        $("#runtime-capture").text(captureHealthy ? "Dang chay" : "Khong hoat dong");
        $("#runtime-capture-note").text(
            captureHealthy
                ? "Capture dang theo doi luong mang, timeout flow " + runtimeState.flow_timeout + "s."
                : "Capture thread khong hoat dong. Kiem tra quyen sniff va log runtime."
        );

        $("#runtime-worker").text(workerHealthy ? "Dang chay" : "Khong hoat dong");
        $("#runtime-worker-note").text(
            workerHealthy
                ? "Worker dang xu ly flow va ghi alert vao storage."
                : "Worker thread khong hoat dong. Kiem tra queue va log backend."
        );

        $("#runtime-queue").text(queueSize + " / " + queueCapacity);
        $("#runtime-queue-note").text(queueNote);

        $("#runtime-active-flows").text(runtimeState.active_flows || 0);
        $("#runtime-processed-flows").text(runtimeState.processed_flows || 0);
        $("#runtime-dropped-flows").text(runtimeState.dropped_flows || 0);
        $("#runtime-worker-errors").text(runtimeState.worker_errors || 0);
        $("#runtime-uptime").text(formatUptime(runtimeState.uptime_seconds));
        $("#runtime-geolocation").text("GeoIP: " + (runtimeState.geolocation_enabled ? "bat" : "tat"));
        $("#runtime-explanations").text("LIME: " + (runtimeState.explanations_enabled ? "bat" : "tat"));
    }

    function runtimeFailureMessage() {
        return "Khong the doc trang thai runtime.";
    }

    function renderControls() {
        var pauseButton = $("#toggle-live");
        var priorityButton = $("#toggle-priority");
        var statusText = $("#table-status");

        pauseButton.toggleClass("is-active", liveUpdatesPaused);
        priorityButton.toggleClass("is-active", priorityOnly);

        if (liveUpdatesPaused) {
            pauseButton.text("Tiep tuc cap nhat");
            statusText.text("Bang chinh dang duoc giu nguyen de thao tac. Co " + bufferedCount + " ban cap nhat moi cho hien thi.");
        } else if (hasActiveFilters()) {
            pauseButton.text("Tam dung cap nhat bang");
            statusText.text("Du lieu lich su dang duoc doc tu SQLite theo bo loc hien tai.");
        } else if (priorityOnly) {
            pauseButton.text("Tam dung cap nhat bang");
            statusText.text("Dang loc rieng cac ban ghi can uu tien phan tich.");
        } else {
            pauseButton.text("Tam dung cap nhat bang");
            statusText.text("Bang dang tu dong cap nhat theo thoi gian thuc.");
        }

        priorityButton.text(priorityOnly ? "Hien toan bo ban ghi" : "Chi xem ban ghi can uu tien");
    }

    function refreshDashboard() {
        renderMainTable();
        renderPriorityTable();
        renderStats(latestIps);
        renderChart(latestIps);
        renderControls();
        renderRuntimeStatus();
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
                $("#table-status").text("Khong the tai lich su alert tu database.");
            });
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
                $("#runtime-capture").text("Khong ro");
                $("#runtime-worker").text("Khong ro");
                $("#runtime-queue").text("Khong ro");
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
    loadRuntimeStatus();
    runtimePollHandle = window.setInterval(loadRuntimeStatus, 5000);

    $(window).on("beforeunload", function () {
        if (runtimePollHandle) {
            window.clearInterval(runtimePollHandle);
        }
    });
});

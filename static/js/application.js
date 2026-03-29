$(document).ready(function () {
    var socket = io.connect("http://" + document.domain + ":" + location.port + "/test");
    var recentFlows = [];
    var maxRows = 20;

    function riskClass(risk) {
        var normalized = String(risk || "").toLowerCase();
        if (normalized.indexOf("very high") >= 0) {
            return "risk-very-high";
        }
        if (normalized.indexOf("high") >= 0) {
            return "risk-high";
        }
        if (normalized.indexOf("medium") >= 0) {
            return "risk-medium";
        }
        if (normalized.indexOf("low") >= 0) {
            return "risk-low";
        }
        return "risk-minimal";
    }

    function probabilityLabel(value) {
        var parsed = Number(value);
        if (Number.isNaN(parsed)) {
            return value;
        }
        return (parsed * 100).toFixed(1) + "%";
    }

    function renderStats(ips) {
        var highRisk = recentFlows.filter(function (flow) {
            return ["High", "Very High"].indexOf(flow.risk) >= 0;
        }).length;
        var benign = recentFlows.filter(function (flow) {
            return String(flow.prediction).toLowerCase() === "benign";
        }).length;

        $("#stat-total").text(recentFlows.length);
        $("#stat-high-risk").text(highRisk);
        $("#stat-benign").text(benign);
        $("#stat-sources").text(ips.length);
    }

    function renderTable() {
        var tableBody = "";

        if (!recentFlows.length) {
            tableBody = '<tr><td colspan="14" class="empty-state">Waiting for live flow data. Start capture traffic and this dashboard will populate automatically.</td></tr>';
        } else {
            for (var i = recentFlows.length - 1; i >= 0; i--) {
                var flow = recentFlows[i];
                var predictionClass = String(flow.prediction).toLowerCase() === "benign" ? "is-benign" : "is-alert";
                tableBody += "<tr>";
                tableBody += "<td><strong>#"+ flow.id +"</strong></td>";
                tableBody += "<td>" + flow.src + "</td>";
                tableBody += "<td>" + flow.srcPort + "</td>";
                tableBody += "<td>" + flow.dst + "</td>";
                tableBody += "<td>" + flow.dstPort + "</td>";
                tableBody += "<td>" + flow.protocol + "</td>";
                tableBody += "<td>" + flow.start + "</td>";
                tableBody += "<td>" + flow.lastSeen + "</td>";
                tableBody += "<td>" + flow.appName + '<span class="cell-secondary">PID ' + flow.pid + "</span></td>";
                tableBody += "<td>" + flow.pid + "</td>";
                tableBody += '<td><span class="prediction-pill ' + predictionClass + '">' + flow.prediction + "</span></td>";
                tableBody += "<td>" + probabilityLabel(flow.probability) + "</td>";
                tableBody += '<td><span class="risk-pill ' + riskClass(flow.risk) + '">' + flow.risk + "</span></td>";
                tableBody += '<td><a class="action-link" href="/flow-detail?flow_id=' + flow.id + '">Inspect</a></td>';
                tableBody += "</tr>";
            }
        }

        $("#details tbody").html(tableBody);
    }

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

        if (recentFlows.length >= maxRows) {
            recentFlows.shift();
        }

        recentFlows.push(flow);
        renderTable();

        var ips = msg.ips || [];
        myChart.data.labels = [];
        myChart.data.datasets[0].data = [];
        for (var i = 0; i < ips.length; i++) {
            myChart.data.labels.push(ips[i].SourceIP);
            myChart.data.datasets[0].data.push(ips[i].count);
        }
        myChart.update();

        renderStats(ips);
    });
});

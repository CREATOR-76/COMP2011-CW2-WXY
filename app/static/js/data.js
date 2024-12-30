$(document).ready(function() {
    const productId = 1; // 设置产品 ID，动态传入
    $.get(`/sales_data/${productId}`, function(data) {
        if (data.dates && data.sales && data.profits) {
            const ctx = document.getElementById('salesChart').getContext('2d');
            const salesChart = new Chart(ctx, {
                type: 'line', // 图表类型可以是 'line', 'bar', 等
                data: {
                    labels: data.dates,
                    datasets: [{
                        label: 'Sales Quantity',
                        data: data.sales,
                        borderColor: 'rgba(75, 192, 192, 1)',
                        fill: false
                    }, {
                        label: 'Total Profit',
                        data: data.profits,
                        borderColor: 'rgba(255, 99, 132, 1)',
                        fill: false
                    }]
                },
                options: {
                    responsive: true,
                    plugins: {
                        legend: {
                            position: 'top',
                        },
                        tooltip: {
                            mode: 'index',
                            intersect: false
                        }
                    },
                    interaction: {
                        mode: 'index',
                        intersect: false
                    },
                    scales: {
                        x: {
                            title: {
                                display: true,
                                text: 'Date'
                            }
                        },
                        y: {
                            title: {
                                display: true,
                                text: 'Amount'
                            }
                        }
                    }
                }
            });
        } else {
            console.error("API response data is incomplete.");
        }
    }).fail(function() {
        console.error("Failed to fetch data from the API.");
    });
});

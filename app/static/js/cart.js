document.addEventListener('DOMContentLoaded', function () {
    const checkboxes = document.querySelectorAll('.checkbox');
    const totalPriceElement = document.getElementById('total-price');
    const selectedCountElement = document.getElementById('selected-count');
    const clearCartButton = document.getElementById('clear-cart');

    // 更新总价和选中数量
    function updateSummary() {
        let totalPrice = 0;
        let selectedCount = 0;

        checkboxes.forEach(checkbox => {
            if (checkbox.checked) {
                selectedCount++;
                totalPrice += parseFloat(checkbox.dataset.price); // 从 data-price 属性读取价格
            }
        });

        totalPriceElement.textContent = totalPrice.toFixed(2);
        selectedCountElement.textContent = selectedCount;
    }

    // 单选框改变时更新总价
    checkboxes.forEach(checkbox => {
        checkbox.addEventListener('change', function () {
            updateSummary();
        });
    });

    // 初始化总价和选中数量
    updateSummary();
});

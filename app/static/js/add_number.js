document.addEventListener('DOMContentLoaded', function () {
    const decrementBtn = document.querySelector('.decrement');
    const incrementBtn = document.querySelector('.increment');
    const quantityInput = document.querySelector('#quantity');

    // 获取最大值和最小值
    const minQuantity = parseInt(quantityInput.min);
    const maxQuantity = parseInt(quantityInput.max);

    // 减号按钮点击事件
    decrementBtn.addEventListener('click', function () {
        let currentValue = parseInt(quantityInput.value);
        if (currentValue > minQuantity) {
            quantityInput.value = currentValue - 1;
        }
    });

    // 加号按钮点击事件
    incrementBtn.addEventListener('click', function () {
        let currentValue = parseInt(quantityInput.value);
        if (currentValue < maxQuantity) {
            quantityInput.value = currentValue + 1;
        }
    });

    // 防止用户输入无效值
    quantityInput.addEventListener('input', function () {
        // 如果输入不是有效数字，恢复为最小值
        let currentValue = parseInt(quantityInput.value);
        if (isNaN(currentValue) || currentValue < minQuantity) {
            quantityInput.value = minQuantity;
        } else if (currentValue > maxQuantity) {
            quantityInput.value = maxQuantity;
        }
    });
});
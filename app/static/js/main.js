document.addEventListener('DOMContentLoaded', function () {
        // 获取所有“加入购物车”按钮
        const addToCartButtons = document.querySelectorAll('.add-to-cart');

        addToCartButtons.forEach(button => {
            button.addEventListener('click', function () {
                const productId = this.dataset.productId;
                const quantityElement = document.querySelector('#quantity');
                const quantity = quantityElement ? quantityElement.value : 1;

                // 使用Fetch API发送AJAX请求
                fetch('/add_to_cart', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                        'X-CSRFToken': '{{ csrf_token() }}'  // 如果使用Flask-WTF，需添加CSRF Token
                    },
                    body:  `product_id=${productId}&quantity=${quantity}`
                })
                .then(response => response.json())
                .then(data => {
                    if (data.status === 'success') {
                        alert(data.message);  // 显示成功提示
                    } else {
                        alert('Failed to add items to cart!');
                    }
                })
                .catch(error => {
                    console.error('Error:', error);
                    alert('An error has occurred, please try again later!');
                });
            });
        });
    });
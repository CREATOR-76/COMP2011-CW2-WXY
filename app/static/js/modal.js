
$(document).ready(function (){
    $(".edit_profile").click(function(){
    $("#myModal").css("display", "block");
});
    $(".close").click(function() {
        $("#myModal").css("display", "none");
});

    $("#changePasswordBtn").click(function() {
        $("#passwordForm").css("display", "block");  // 显示密码修改表单
        $("#profileFrom").css("display", "none");  // 隐藏个人信息表单
    });

    // 点击“返回个人信息”按钮，切换回个人信息表单
    $("#backToInfoBtn").click(function() {
        $("#passwordForm").css("display", "none");  // 隐藏密码修改表单
        $("#profileFrom").css("display", "block");  // 显示个人信息表单
    });
});
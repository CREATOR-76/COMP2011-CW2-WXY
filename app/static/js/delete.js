function confirmDelete(){
    const ans = confirm("Are you sure you want to delete ?");
    if (ans===false) {
        event.preventDefault();
        return false;
    }else {
        alert("successfully delete")
        return true

    }
}
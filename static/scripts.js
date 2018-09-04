function homePhoneStyle(form) {
    num = form.home.value;
    if (num.length == 4) {
        if (!isNaN(num.charAt(3))) {
            parts = [num.slice(0,3), num.slice(3,4)];
            fNum = parts[0] + "-" + parts[1];
            form.home.value = fNum;
        }
    } else if (num.length == 8) {
        if (!isNaN(num.charAt(7))) {
            parts = [num.slice(0,7), num.slice(7,8)];
            fNum = parts[0] + "-" + parts[1];
            form.home.value = fNum;
        }
    }
}

function cellPhoneStyle(form) {
    num = form.cell.value;
    if (num.length == 4) {
        if (!isNaN(num.charAt(3))) {
            parts = [num.slice(0,3), num.slice(3,4)];
            fNum = parts[0] + "-" + parts[1];
            form.cell.value = fNum;
        }
    } else if (num.length == 8) {
        if (!isNaN(num.charAt(7))) {
            parts = [num.slice(0,7), num.slice(7,8)];
            fNum = parts[0] + "-" + parts[1];
            form.cell.value = fNum;
        }
    }
}

function autoUserPass(form) {
    var inputName = form.name.value;
    var name = inputName.split(" ");
    for (var i = 0; i < name.length; i++) {
        name[i] = name[i].toLowerCase();
    }
    form.username.value = name.join(".");
    if (inputName) {
        form.password.value = "1234";
        form.confirm.value = "1234";
    }

}

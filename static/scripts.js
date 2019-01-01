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

function formatDate(form) {
    inputDate = form.date.value;
    if (inputDate.length == 5) {
        if (!isNaN(inputDate.charAt(4))) {
            parts = [inputDate.slice(0,4), inputDate.slice(4,5)];
            fDate = parts[0] + "-" + parts[1];
            form.date.value = fDate;
        }
    } else if (inputDate.length == 8) {
        if (!isNaN(inputDate.charAt(7))) {
            parts = [inputDate.slice(0,7), inputDate.slice(7,8)];
            fDate = parts[0] + "-" + parts[1];
            form.date.value = fDate;
        }
    }
}
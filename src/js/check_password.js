function checkPasswordMatch() {
  var password = $("#password").val();
  var confirmPassword = $("#check_password").val();

  if (password != confirmPassword){
    $("#divCheckPasswordMatch").html("Passwords do not match!");
    $("input[type=submit]").attr("disabled", true);
  }
  else{
    $("#divCheckPasswordMatch").html("Passwords match.");
    $("input[type=submit]").removeAttr("disabled");
  }
}

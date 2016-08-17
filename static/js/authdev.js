
function auth_dev_init(callback)
{
    $("#login-button").click(function ()
    {
        var username = $('#login_username').val();
        var password = $('#login_password').val();

        opener[callback](username, password);

        window.close();

        return false;
    });
}
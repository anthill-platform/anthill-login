
function auth_dev_init()
{
    $("#login-form").submit(function (event)
    {
        var username = $('#login_username').val();
        var password = $('#login_password').val();

        opener["auth_callback"](username, password);

        window.close();

        event.preventDefault();
    });
}
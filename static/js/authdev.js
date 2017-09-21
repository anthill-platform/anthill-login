
function auth_dev_init(callback)
{
    $("#login-form").submit(function (event)
    {
        var username = $('#login_username').val();
        var password = $('#login_password').val();

        opener[callback](username, password);

        window.close();

        event.preventDefault();
    });
}
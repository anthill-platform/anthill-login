
AUTHOPTS = {};

$(function()
{
    $('#signinGoogleButton').click(function()
    {
        form_auth("google");
    });

    $('#signinFacebookButton').click(function()
    {
        form_auth("facebook");
    });

    $('#signinDevButton').click(function()
    {
        form_auth("dev");
    });
});

function form_auth(a_with)
{
    $('#result').html('<i class="fa fa-cog fa-spin fa-2x fa-fw"></i> Please wait');

    auth_with(a_with).fail(function(reason, data, responseText)
    {
        form_failed(reason,
            data,
            responseText);

    }).done(function(token)
    {
        auth_redirect(
            AUTHOPTS["redirect_to"],
            {
                "token": btoa(token)
            });
    });
}

function form_failed(reason, data, responseText)
{
    bootbox.dialog({
        "title": "Unfortunatelly, an error occured",
        "message": "<pre>" + responseText + "</pre>",
        "buttons":
        {
            "proceed":
            {
                "title": "Proceed"
            }
        }

    });
}

function authform_init(
    client_ids,
    redirect_to,
    gamespace,
    scopes,
    should_have,
    attach_to,
    auth_as,

    callback)
{
    AUTHOPTS["redirect_to"] = redirect_to;

    $(function()
    {
        var sns = {
            "dev": {}
        };

        $.extend(sns, client_ids);

        var settings = {
            "gamespace": gamespace,
            "scopes": scopes,
            "should_have": should_have,
            "attach_to": attach_to,
            "auth_as": auth_as,
            "sns": sns
        };

        auth_init('', settings).done(callback);
    });
}
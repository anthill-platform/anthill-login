
OPTS = {};

REDIRECT_URI = document.location.origin + "/auth/oauth2callback";

function OAuth2Authentication(name, form_width, form_height)
{
    this.name = name;
    this.form_width = form_width || 655;
    this.form_height = form_height || 430;
}

OAuth2Authentication.prototype.auth = function(gamespace)
{
    var d = $.Deferred();
    var zis = this;

    window.auth_callback = function(code)
    {
        d.resolve(zis.name, {
            "code": code,
            "redirect_uri": REDIRECT_URI
        });
    };

    window.popup("/auth/" + this.name + "?" + $.param({
        "gamespace": gamespace,
        "redirect_uri": REDIRECT_URI
    }), "Authenticate", this.form_width, this.form_height);

    return d.promise();
};

function DevAuthentication()
{

}

DevAuthentication.prototype.auth = function(gamespace)
{
    var d = $.Deferred();

    window.auth_callback = function(username, password)
    {
        d.resolve("dev", {
            "username": username,
            "key": password
        })
    };

    window.popup(document.location.origin + "/auth/dev", "Authenticate", 360, 380);

    return d.promise();
};


AUTHENTICATION_METHODS = {
    "facebook": new OAuth2Authentication("facebook", 655, 430),
    "vk": new OAuth2Authentication("vk", 655, 430),
    "google": new OAuth2Authentication("google", 500, 500),
    "dev": new DevAuthentication()
};

function auth_with(social_name)
{
    var d = $.Deferred();

    var social = AUTHENTICATION_METHODS[social_name];

    var auth = social.auth(OPTS.gamespace);
    auth.done(function(social, data)
    {
        authenticate(social, data).done(function(token)
        {
            d.resolve(token)
        }).fail(function(reason, data, responseText)
        {
            d.reject(reason, data, responseText);
        });
    }).fail(function(reason, data, responseText)
    {
        d.reject(reason, data, responseText);
    });

    return d.promise();
}

function parse_url_arguments(location){
    var vars = {}, hash;
    var hashes = location.href.slice(location.href.indexOf('?') + 1).split('&');

    for(var i = 0; i < hashes.length; i++)
    {
        hash = hashes[i].split('=');
        vars[hash[0]] = hash[1];
    }

    return vars;
}

function auth_init(location, options)
{
    OPTS["location"] = location;
    OPTS["gamespace"] = options.gamespace;
    OPTS["scopes"] = options.scopes || "";
    OPTS["should_have"] = options.should_have || "*";
    OPTS["attach_to"] = options.attach_to || "";
    OPTS["auth_as"] = options.auth_as || "";
}

function resolve_conflict(method, resolve_with, resolve_token)
{
    var d = $.Deferred();

    var params = {
        "resolve_with": resolve_with,
        "resolve_method": method,
        "access_token": resolve_token,
        "scopes": OPTS.scopes,
        "full": true,
        "should_have": OPTS.should_have,
        "attach_to": OPTS["attach_to"]
    };

    $.post(OPTS.location + "/resolve", params, function(data, textStatus)
    {
        if (textStatus == "success")
        {
            var token = data["token"];

            d.resolve(token);
        }
    }, "json").fail(function(reason, text, statusText)
    {
        d.reject(statusText, {}, reason.responseText);
    });

    return d.promise();
}

function auth_redirect(to, data)
{
    var url = new URL(to);

    for (var key in data)
    {
        url.searchParams.set(key, data[key]);
    }

    document.location.href = url.href;
}

function render_account(parent, account)
{
    var profile_avatar = account.profile["avatar"];
    var profile_name = account.profile["name"];

    var time_created = account.profile["@time_created"];
    var time_updated = account.profile["@time_updated"];

    if (profile_avatar != null || profile_name != null)
    {
        var node = $('<div></div>').appendTo(parent);

        if (profile_avatar != null)
        {
            $('<img class="img-circle" width="100px" src="' + profile_avatar + ' ">').appendTo(node);
        }
        if (profile_name != null)
        {
            $('<h3>' + profile_name + '</h3>').appendTo(node);
        }
    }
    else
    {
        if ($.isEmptyObject(account.profile))
        {
            parent.append('<p>( No profile )</p>');
        }
        else
        {
            var profile_text = JSON.stringify(account.profile, null, 4);
            parent.append('<p><code>' + profile_text + '</code></p>');
        }
    }

    function time(time)
    {
        var t = new Date(time * 1000);
        return t.toDateString() + ' ' + t.toTimeString();
    }

    if (time_created != null)
    {
        parent.append('<p>Created: ' + time(time_created) + '</p>');
    }

    if (time_updated != null)
    {
        parent.append('<p>Last updated: ' + time(time_updated) + '</p>');
    }
}

function conflict(response)
{
    var d = $.Deferred();

    var reason = response["result_id"];
    var resolve_token = response["resolve_token"];

    if (reason == "merge_required")
    {
        // well, that's merge required
        var accounts = response["accounts"];

        var local = accounts["local"];
        var remote = accounts["remote"];

        render_account($('#account-ismine'), remote);

        $('#form-ismine').modal();

        $('#ismine-yes').on("click", function()
        {
            $('#form-ismine').modal('hide');
            $('#conflict-choose').modal();

            var account_choose = $('#account-choose');
            var row = $('<div align="center"></div>').appendTo(account_choose);

            for (var account in accounts)
            {
                var resolve = account;
                var data = accounts[account];

                var select = $('<div class="col-sm-6" style="text-align: center;"></div>').appendTo(row);

                var button = $('<p><a href="#" class="btn btn-danger" role="button">Use account @' +
                    data["account"] + '</a></p><hr>').appendTo(select);

                (function(resolve)
                {
                    button.click(function()
                    {
                        $('#conflict-choose').modal('hide');
                        $('#conflict-progress').modal();

                        resolve_conflict("merge_required", resolve, resolve_token).done(function(token)
                        {
                            d.resolve(token);
                        }).fail(function(reason, text, statusText)
                        {
                            d.reject(reason, text, statusText);
                        });
                    });
                })(resolve);


                render_account(select, data);
            }
        });

        $('#ismine-no').one("click", function()
        {
            $('#conflict-ismine').modal('hide');
            $('#conflict-progress').modal();

            resolve_conflict("merge_required", "not_mine", resolve_token).done(function(token)
            {
                d.resolve(token);
            }).fail(function(reason, text, statusText)
            {
                d.reject(reason, text, statusText);
            });
        });
    } else
    if (reason == "multiple_accounts_attached")
    {
        var accounts = response["accounts"];

        $('#conflict-choose').modal();

        var account_choose = $('#account-choose').html('');
        var row = $('<div align="center"></div>').appendTo(account_choose);

        for (var account in accounts)
        {
            var resolve = account;
            var data = accounts[account];

            var select = $('<div class="col-sm-6" style="text-align: center;"></div>').appendTo(row);

            var button = $('<p><a href="#" class="btn btn-danger" role="button">Use account @' +
                data["account"] + '</a></p><hr>').appendTo(select);

            (function(data)
            {
                button.click(function()
                {
                    $('#conflict-choose').modal('hide');
                    $('#conflict-progress').modal();

                    resolve_conflict("multiple_accounts_attached", data["account"], resolve_token).done(function(token)
                    {
                        d.resolve(token);
                    }).fail(function(reason, text, statusText)
                    {
                        d.reject(reason, text, statusText);
                    });
                });
            })(data);


            render_account(select, data);
        }
    }

    return d.promise();
}

function authenticate(credential, data)
{
    var d = $.Deferred();

    var params = {
        "credential": credential,
        "gamespace": OPTS["gamespace"],
        "scopes": OPTS["scopes"],
        "as": OPTS["auth_as"],
        "full": true,
        "should_have": OPTS["should_have"]
    };

    if (OPTS["attach_to"] != "")
    {
        params["attach_to"] = OPTS["attach_to"];
    }

    $.extend(params, data);
    $.post(OPTS.location + "/auth", params, function(data, textStatus)
    {
        if (textStatus == "success")
        {
            var token = data["token"];
            d.resolve(token);
        }
    }, "json").fail(function(data)
    {
        var status = data.status;

        var response = $.parseJSON(
            data.responseText
        );

        var result_id = response["result_id"];

        switch (status)
        {
            case 409:
            case 300:
            {
                var resolve_token = response["resolve_token"];

                $('#auth-root').load(OPTS.location + "/static/js/conflict.in.html", function()
                {
                    conflict(response).fail(function(reason, data, responseText)
                    {
                        d.reject(
                            reason,
                            data,
                            responseText);

                    }).done(function(token)
                    {
                        d.resolve(token);
                    });
                });

                break;
            }
            default:
            {
                d.reject(
                    "unknown",
                    response, data.responseText);

                break;
            }
        }
    });

    return d.promise();
}

function popup(url, title, w, h)
{
    var dualScreenLeft = window.screenLeft != undefined ? window.screenLeft : screen.left;
    var dualScreenTop = window.screenTop != undefined ? window.screenTop : screen.top;

    var width = window.innerWidth ? window.innerWidth : document.documentElement.clientWidth
        ? document.documentElement.clientWidth : screen.width;
    var height = window.innerHeight ? window.innerHeight : document.documentElement.clientHeight
        ? document.documentElement.clientHeight : screen.height;

    var left = ((width / 2) - (w / 2)) + dualScreenLeft;
    var top = ((height / 2) - (h / 2)) + dualScreenTop;
    var newWindow = window.open(url, title, 'scrollbars=no, width=' + w + ', height=' + h + ', top=' +
        top + ', left=' + left);

    if (window.focus && newWindow != undefined)
    {
        newWindow.focus();
    }

    return newWindow;
}
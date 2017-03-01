function toggleTag(el){
    var btn = $(el);
    var tagId = parseInt(btn.attr("data-tag-id"));
    var libraryId = parseInt(btn.attr("data-library-id"));
    btn.attr({disabled: true});
    var add = !btn.hasClass("btn-success");
    var libraryTagPair = {tagId: tagId, libraryId: libraryId};
    $.ajax({
        url: add ? Routes.addTag : Routes.removeTag,
        method: 'POST',
        //dataType: 'json',
        data: JSON.stringify(
            add ? { libraryTagPair: libraryTagPair, contextDependent: false} : libraryTagPair
        ),
        contentType : 'application/json',
        success: function(){
            if(add){
                btn.addClass("btn-success");
            }else{
                btn.removeClass("btn-success");
            }
            btn.attr({disabled: false});
            //alert("SUCCESS "+add);
        },
        error: function(){
            alert("FAILED!");
            btn.addClass("btn-danger");
            // Can't enable the button as we can't be sure about the current state
        }/*,
        complete: function(a, b){
            console.log("complete", a, b);
            alert(["complete", a, b]);
        }*/
    });
}
function toggleClassified(el){
    var btn = $(el);
    var libraryId = parseInt(btn.attr("data-library-id"));
    btn.attr({disabled: true});
    var classifiedNewValue = !btn.hasClass("btn-success");
    $.ajax({
        url: Routes.controllers.Application.setClassified(classifiedNewValue).url,
        method: 'POST',
        contentType : 'application/json',
        data: ""+libraryId,
        success: function(){
            if(classifiedNewValue){
                btn.addClass("btn-success");
            }else{
                btn.removeClass("btn-success");
            }
            btn.attr({disabled: false});
        },
        error: function(){
            alert("FAILED!");
            btn.addClass("btn-danger");
        }
    });
}

function updatePosition(){
    // document.getElementById(…) is used over $('#'+…) in order to reduce attack surface: It does not look like a good idea to pass untrusted input to “omnipotent” `$` function.
    $.scrollTo(document.getElementById(location.hash.substr(1)), {offset: -$('#navbar').height()});
}
function lazyLoad(el){
    var $el = $(el);
    var url = $el.attr("data-lazyload-url");
    function setUrl(newUrl){
      $el.attr("data-lazyload-url", newUrl);
    }
    if(url){
        $el.html($('<div class="progress">')
          .append(
            $('<div class="progress-bar progress-bar-striped active" role="progressbar" style="width: 100%;">Loading…</div>')
          )
        );
        $el.load(url, function( response, status, xhr ) {
            if ( status == "error" ) {
                $el.html("Error when loading data");
                setUrl(url);
            }
        });
        setUrl(null);
    }
}

$(window).bind('hashchange', function(e) { updatePosition(); });
$(window).bind('load', function(e) { updatePosition(); });
$(window).bind('show.bs.collapse', function(e){ lazyLoad(e.target); });
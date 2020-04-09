//document.querySelector("#itemList").classList.add("growsandstays");
const colls = document.querySelectorAll(".drawer");

//TODO: rename
for (let coll of colls) {
  coll.onclick = () => {
    const content = coll.nextElementSibling;
    if (content.style.maxHeight) {
      content.style.maxHeight = null;
    } else {
      content.style.maxHeight = calcContentHeight() + "px";
      content.style.height = calcContentHeight() + "px";

      for (let c of colls) {
        if (c != coll && content.style.maxHeight) {
          c.nextElementSibling.style.maxHeight = null;
        }
      }
    }

  }
}

const $ = document.querySelector.bind(document);

function cssVarGetter(varName) {
  return getComputedStyle(document.documentElement)
    .getPropertyValue(varName);
}

function calcContentHeight() {
  let left = $('#itemList').offsetHeight - parseInt(cssVarGetter('--label-height')) * 4 - parseInt(cssVarGetter('--item-margin')) * 4;
  if(left <= 0){
    left = 300;
  }
  return left;
}

function storeValue(id) {
  let ele = $(id);

  ele.onblur = _ => {
    localStorage.setItem(id, ele.value);
  };

  if (localStorage.getItem(id)) {
    ele.value = localStorage.getItem(id);
  }

}

storeValue('#usernameInput');
storeValue('#roomInput');


/*
*/

function makeid(length) {
  var result = '';
  var characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  var charactersLength = characters.length;
  for (var i = 0; i < length; i++) {
    result += characters.charAt(Math.floor(Math.random() * charactersLength));
  }
  return result;
}

function blocker(secodes) {
  return new Promise((y, n) => {
    setTimeout(function () {
      y();
    }, secodes * 1000);
  })
}

async function loginEnter(event) {
  if (event.keyCode === 13) {
    let username, room;

    if ($('#usernameInput').value === '') {
      username = makeid(10);
    } else {
      username = $('#usernameInput').value;
    }

    if ($('#roomInput').value === '') {
      room = makeid(10);
    } else {
      room = $('#roomInput').value;
    }

    $("#maskLayer").classList.add("disappear");
    await blocker(0.5);
    $("#maskLayer").style.display = 'none';


    $("#itemList").classList.add("fadein");

    // await blocker(0.5);

    $("#myselfItem").classList.add("slidein");

    await blocker(0.5);

    $("#participantItem").classList.add("slidein");

    await blocker(0.8);

    // $("#participantsContent").style.maxHeight = calcContentHeight() + 'px';


    $("#participantsContent").style.maxHeight = calcContentHeight() + 'px';

    let times = 200;
    let step = calcContentHeight() / times;
    let index = 0;
    let height = 0;
    let frame = 4;
    let id = setInterval(function () {
      if (index++ < times) {
        height += step;
        $("#participantsContent").style.height = height + 'px';
      } else {
        clearInterval(id);
      }
    }, frame);

    $("#chatItem").classList.add("slidein");

    $("#pollItem").classList.add("slidein");
    
    await blocker(0.8)
    $("#videoList").classList.add("fadein");

  }
}

$('#usernameInput').onkeydown = loginEnter;
$('#roomInput').onkeydown = loginEnter;

async function main() {

  let stream = await navigator.mediaDevices.getUserMedia({ video: true });
  let video = document.querySelector('#localVideo');
  video.srcObject = stream;
}

main();
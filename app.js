
/* global networking */

const 
  bodyParser = require('body-parser'),
  config = require('config'),
  crypto = require('crypto'),
  express = require('express'),
  https = require('https'),  
  request = require('request'),
  networking = require('./bot.network'),
  stringUtils = require('./bot.string-utils');
  
const 
    charLimitTitle = 80,
    charLimitButtonTitle = 20,
    charLimitTextMsg = 320; 
  
var app = express();
app.set('port', process.env.PORT || 5000);
app.set('view engine', 'ejs');
app.use(bodyParser.json({ verify: verifyRequestSignature }));
app.use(express.static('public'));


/*
 * Be sure to setup your config values before running this code. You can 
 * set them using environment variables or modifying the config file in /config.
 *
 */

// App Secret can be retrieved from the App Dashboard
const APP_SECRET = (process.env.MESSENGER_APP_SECRET) ? 
  process.env.MESSENGER_APP_SECRET :
  config.get('appSecret');

// Arbitrary value used to validate a webhook
const VALIDATION_TOKEN = (process.env.MESSENGER_VALIDATION_TOKEN) ?
  (process.env.MESSENGER_VALIDATION_TOKEN) :
  config.get('validationToken');

// Generate a page access token for your page from the App Dashboard
const PAGE_ACCESS_TOKEN = (process.env.MESSENGER_PAGE_ACCESS_TOKEN) ?
  (process.env.MESSENGER_PAGE_ACCESS_TOKEN) :
  config.get('pageAccessToken');

// URL where the app is running (include protocol). Used to point to scripts and 
// assets located at this address. 
const SERVER_URL = (process.env.SERVER_URL) ?
  (process.env.SERVER_URL) :
  config.get('serverURL');

if (!(APP_SECRET && VALIDATION_TOKEN && PAGE_ACCESS_TOKEN && SERVER_URL)) {
  console.error("Missing config values");
  process.exit(1);
}

/*
 * Use your own validation token. Check that the token used in the Webhook 
 * setup is the same token used here.
 *
 */
app.get('/webhook', function(req, res) {
  if (req.query['hub.mode'] === 'subscribe' &&
      req.query['hub.verify_token'] === VALIDATION_TOKEN) {
    console.log("Validating webhook");
    res.status(200).send(req.query['hub.challenge']);
  } else {
    console.error("Failed validation. Make sure the validation tokens match.");
    res.sendStatus(403);          
  }  
});


/*
 * All callbacks for Messenger are POST-ed. They will be sent to the same
 * webhook. Be sure to subscribe your app to your page to receive callbacks
 * for your page. 
 * https://developers.facebook.com/docs/messenger-platform/product-overview/setup#subscribe_app
 *
 */
app.post('/webhook', function (req, res) {
  var data = req.body;

  // Make sure this is a page subscription
  if (data.object == 'page') {
    // Iterate over each entry
    // There may be multiple if batched
    data.entry.forEach(function(pageEntry) {
      var pageID = pageEntry.id;
      var timeOfEvent = pageEntry.time;

      // Iterate over each messaging event
      pageEntry.messaging.forEach(function(messagingEvent) {
        if (messagingEvent.optin) {
          receivedAuthentication(messagingEvent);
        } else if (messagingEvent.message) {
          receivedMessage(messagingEvent);
        } else if (messagingEvent.delivery) {
          receivedDeliveryConfirmation(messagingEvent);
        } else if (messagingEvent.postback) {
          receivedPostback(messagingEvent);
        } else if (messagingEvent.read) {
          receivedMessageRead(messagingEvent);
        } else if (messagingEvent.account_linking) {
          receivedAccountLink(messagingEvent);
        } else {
          console.log("Webhook received unknown messagingEvent: ", messagingEvent);
        }
      });
    });

    // Assume all went well.
    //
    // You must send back a 200, within 20 seconds, to let us know you've 
    // successfully received the callback. Otherwise, the request will time out.
    res.sendStatus(200);
  }
});

/*
 * This path is used for account linking. The account linking call-to-action
 * (sendAccountLinking) is pointed to this URL. 
 * 
 */
app.get('/authorize', function(req, res) {
  var accountLinkingToken = req.query['account_linking_token'];
  var redirectURI = req.query['redirect_uri'];

  // Authorization Code should be generated per user by the developer. This will 
  // be passed to the Account Linking callback.
  var authCode = "1234567890";

  // Redirect users to this URI on successful login
  var redirectURISuccess = redirectURI + "&authorization_code=" + authCode;

  res.render('authorize', {
    accountLinkingToken: accountLinkingToken,
    redirectURI: redirectURI,
    redirectURISuccess: redirectURISuccess
  });
});

/*
 * Verify that the callback came from Facebook. Using the App Secret from 
 * the App Dashboard, we can verify the signature that is sent with each 
 * callback in the x-hub-signature field, located in the header.
 *
 * https://developers.facebook.com/docs/graph-api/webhooks#setup
 *
 */
function verifyRequestSignature(req, res, buf) {
  var signature = req.headers["x-hub-signature"];

  if (!signature) {
    // For testing, let's log an error. In production, you should throw an 
    // error.
    console.error("Couldn't validate the signature.");
  } else {
    var elements = signature.split('=');
    var method = elements[0];
    var signatureHash = elements[1];

    var expectedHash = crypto.createHmac('sha1', APP_SECRET)
                        .update(buf)
                        .digest('hex');

    if (signatureHash != expectedHash) {
      throw new Error("Couldn't validate the request signature.");
    }
  }
}

/*
 * Authorization Event
 *
 * The value for 'optin.ref' is defined in the entry point. For the "Send to 
 * Messenger" plugin, it is the 'data-ref' field. Read more at 
 * https://developers.facebook.com/docs/messenger-platform/webhook-reference/authentication
 *
 */
function receivedAuthentication(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;
  var timeOfAuth = event.timestamp;

  // The 'ref' field is set in the 'Send to Messenger' plugin, in the 'data-ref'
  // The developer can set this to an arbitrary value to associate the 
  // authentication callback with the 'Send to Messenger' click event. This is
  // a way to do account linking when the user clicks the 'Send to Messenger' 
  // plugin.
  var passThroughParam = event.optin.ref;

  console.log("Received authentication for user %d and page %d with pass " +
    "through param '%s' at %d", senderID, recipientID, passThroughParam, 
    timeOfAuth);

  // When an authentication is received, we'll send a message back to the sender
  // to let them know it was successful.
  sendTextMessage(senderID, "Authentication successful");
}

/*
 * Message Event
 *
 * This event is called when a message is sent to your page.
 * Read more at https://developers.facebook.com/docs/messenger-platform/webhook-reference/message-received
 *
 */
function receivedMessage(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;
  var timeOfMessage = event.timestamp;
  var message = event.message;

  console.log("Received message for user %d and page %d at %d with message:", 
    senderID, recipientID, timeOfMessage);
  console.log(JSON.stringify(message));

  var isEcho = message.is_echo;
  var messageId = message.mid;
  var appId = message.app_id;
  var metadata = message.metadata;

  // You may get a text or attachment but not both
  var messageText = message.text;
  var messageAttachments = message.attachments;
  var quickReply = message.quick_reply;

  if (isEcho) {
    // Just logging message echoes to console
    console.log("Received echo for message %s and app %d with metadata %s", 
      messageId, appId, metadata);
    return;
  } else if (quickReply) {
    var quickReplyPayload = quickReply.payload;
    console.log("Quick reply for message %s with payload %s",
      messageId, quickReplyPayload);
	  switch (quickReplyPayload) {
              case 'CUSTOM_new':
            CUSTOM_new(senderID); 
            break;
              
             case 'CUSTOM_salbar_2':
              CUSTOM_salbar_2(senderID); 
            break; 
                case 'tulhuurug':
            tulhuurug(senderID); 
            break; 
               case 'operator':
              operator(senderID); 
            break;
             case 'tulhuur1':
              CUSTOM_2_1(senderID); 
            break;
              
                 case 'tulhuur3':
              CUSTOM_2_1(senderID); 
            break;
                 case 'tulhuur4':
              CUSTOM_1_3(senderID); 
            break;
                 case 'tulhuur5':
              CUSTOM_3_3(senderID); 
            break;
               case 'maunfunc':
            maunfunc(senderID); 
            break;  
              
		case 'CUSTOM_QUICK_DATA_1GB':
			sendTextMessage(senderID, "1gb гэсэн түлхүүр үгийг 123 дугаарт илгээнэ. Дагалдах эрх үйлчилгээний хоног 30. Үнэ 10.000₮"); 
            break;
		case 'CUSTOM_QUICK_DATA_2GB':
			sendTextMessage(senderID, "2gb гэсэн түлхүүр үгийг 123 дугаарт илгээнэ. Дагалдах эрх үйлчилгээний хоног 30. Үнэ 13.000₮"); 
            break;
		case 'CUSTOM_QUICK_DATA_10GB':
			sendTextMessage(senderID, "10gb гэсэн түлхүүр үгийг 123 дугаарт илгээнэ. Дагалдах эрх үйлчилгээний хоног 60. Үнэ 30.000₮"); 
            break;
	  }
    return;
  }

  if (messageText) {

    switch (messageText) {
      
      case 'Сайн байна уу?':
    case 'Sain baina uu? ':
    case 'Сайнуу':
    case 'Sainuu':
    case 'сайнуу':
    case 'sainuu':
    case 'Байна уу?':
    case 'Baina uu?':
    case 'Бну':
    case 'Bnu':
    case 'bnu':
    case 'бну':
      case 'hi': 
      case 'Yum asuuy':  
      case 'юм асууя':  
      case 'yum asuuya':  
      case 'хүн бну':  
      case 'hun bnu':
      case '123': 
        maunfunc(senderID);
        break; 
    case 'hello':
            CUSTOM_new(senderID); 
            break;
        case 'soap':
            CUSTOM_soap(senderID);
            break;
        case 'Салбар':
     case 'salbar':
         salbarMessage(senderID); 
            break;
          
           case 'Шинэ дугаар':
            case 'шинэ дугаар':
         CUSTOM_2_1_1_key(senderID); 
            break;
             case 'Shake and Share':
            case 'shake and share':
         CUSTOM_1_2_2_1_key(senderID); 
            break;
             
              case 'Карт':
            case 'карт':
         CUSTOM_2_2_2(senderID); 
            break;
             case 'Нэгж':
            case 'нэгж':
         CUSTOM_2_2_2(senderID); 
            break;    
          case 'Смарт home':
            case 'смарт home':
         CUSTOM_2_3(senderID); 
            break;
             case 'УТҮ':
            CUSTOM_1_2(senderID); 
            break; 
                case 'ДТҮ':
            CUSTOM_1_1(senderID); 
            break;
              case 'Модем':
            case 'модем':
         CUSTOM_3_2(senderID); 
            break;
            

              case 'Үнэ':
            case 'үнэ':
         CUSTOM_3_1(senderID); 
            break;
               case 'Лизинг':
            case 'лизинг':
         CUSTOM_2_1_2(senderID); 
            break;
             
                 case 'Монголдоо':
            case 'монголдоо':
         CUSTOM_1_1_2(senderID); 
            break;
            
               
       case 'ip': 
            ip(senderID); 
            break; 
            case 'test': 
            CUSTOM_test(senderID); 
            break; 
      

      default:
        maunfunc(senderID);
    }
  } else if (messageAttachments) {
    sendTextMessage(senderID, "Message with attachment received");
  }
}
function CUSTOM_test(recipientId){
    
   var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "button",
          text: recipientId,
          buttons:[{
            type: "postback",
            payload: "CUSTOM_1",
            title: "Үндсэн үйлчилгээ"
          }]
        }
      }
    }
  };  
  callSendAPI(messageData);
}

function startMessage(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "button",
          text: "Мобайл",
          buttons:[{
            type: "postback",
            payload: "CUSTOM_new",
            title: "Хэрэглэгч тусламж"
          }, {
            type: "postback",
            title: "Үйлчилгээ авах",
            payload: "CUSTOM_dealer"
          }]
        }
      }
    }
  };  

  callSendAPI(messageData);
}

function CUSTOM_new(recipientId){

   var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "button",
          text: "Skytel Messenger-т тавтай морил",
          buttons:[{
            type: "postback",
            payload: "CUSTOM_1",
            title: "Үндсэн үйлчилгээ"
          }, {
            type: "postback",
            title: "Урамшуулал",
            payload: "CUSTOM_2"
          }, {
            type: "postback",
            title: "Гар утас,төхөөрөмж",
            payload: "CUSTOM_3"
          }]
        }
      }
    }
  };  

  callSendAPI(messageData);
}

function CUSTOM_soap(recipientId) {
    var messageData = {
        recipient: {
            id: recipientId
        },
        message: {
            text: "Сайн байн уу",
            metadata: "DEVELOPER_DEFINED_METADATA"
        }
    };

    callSendAPI(messageData);
}
function startUramshuulal(recipientId) {
    
   var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "button",
          text: "Дараах цэснээс сонгоно уу",
          buttons:[{
            type: "postback",
            payload: "CUSTOM_2_1",
            title: "ДТҮ урамшуулал"
          }, {
            type: "postback",
            title: "УТҮ урамшуулал",
            payload: "CUSTOM_2_2"
          }, {
            type: "postback",
            title: "Smart home",
            payload: "CUSTOM_2_3"
          }]
        }
      }
    }
  };  
  callSendAPI(messageData);
}
function CUSTOM_1_2_2_1_key(recipientId) {
    
   var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "button",
          text: "Shake and Share",
          buttons:[{
            type: "postback",
            payload: "CUSTOM_1_2_2_1",
            title: "Shake and Share"
          }]
        }
      }
    }
  };  
  callSendAPI(messageData);
}
function   CUSTOM_2_1_1_key(recipientId) {
    
   var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "button",
          text: "Шинэ дугаар",
          buttons:[{
            type: "postback",
            payload: "CUSTOM_2_1_1",
            title: "Шинэ дугаар"
          }]
        }
      }
    }
  };  
  callSendAPI(messageData);
}
function CUSTOM_2_1(recipientId) {
    
   var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "button",
          text: "Дараах цэснээс сонгоно уу",
          buttons:[{
            type: "postback",
            payload: "CUSTOM_2_1_1",
            title: "Шинэ хэрэглэгч"
          }, {
            type: "postback",
            title: "Гар утасны лизинг",
            payload: "CUSTOM_2_1_2"
          }]
        }
      }
    }
  };  
  callSendAPI(messageData);
}
function CUSTOM_2_2(recipientId) {
    
   var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "button",
          text: "Дараах цэснээс сонгоно уу",
          buttons:[{
            type: "postback",
            payload: "CUSTOM_2_2_1",
            title: "Шинэ хэрэглэгч"
          }, {
            type: "postback",
            title: "Shake & Win",
            payload: "CUSTOM_2_2_2"
          }, {
            type: "postback",
            title: "Shake & Share",
            payload: "CUSTOM_2_2_3"
          }]
        }
      }
    }
  };  
  callSendAPI(messageData);
}
function CUSTOM_2_3(recipientId) {
    
   var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "button",
          text: "Дараах цэснээс сонгоно уу",
          buttons:[{
            type: "postback",
            payload: "CUSTOM_2_3_1",
            title: "Танилцуулга"
          }, {
            type: "postback",
            title: "Бүртгүүлэх заавар",
            payload: "CUSTOM_2_3_2"
          }]
        }
      }
    }
  };  
  callSendAPI(messageData);
}

function CUSTOM_1(recipientId) {
    
   var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "button",
          text: "Дараах цэснээс сонгоно уу",
          buttons:[{
            type: "postback",
            payload: "CUSTOM_1_1",
            title: "Дараа төлбөрт"
          }, {
            type: "postback",
            title: "Урьдчилсан төлбөрт",
            payload: "CUSTOM_1_2"
          }, {
            type: "postback",
            title: "Дата",
            payload: "CUSTOM_1_3"
          }]
        }
      }
    }
  };  
  callSendAPI(messageData);
}
function CUSTOM_1_1(recipientId) {
    
   var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "button",
          text: "Дараах цэснээс сонгоно уу",
          buttons:[{
            type: "postback",
            payload: "CUSTOM_1_1_1",
            title: "Төлбөр тооцоо"
          }, {
            type: "postback",
            title: "МОНГОЛдоо",
            payload: "CUSTOM_1_1_2"
          }, {
            type: "postback",
            title: "Нэмэлт үйлчилгээ",
            payload: "CUSTOM_1_1_3"
          }]
        }
      }
    }
  };  
  callSendAPI(messageData);
}

function CUSTOM_1_2(recipientId) {
    
   var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "button",
          text: "Дараах цэснээс сонгоно уу",
          buttons:[{
            type: "postback",
            payload: "CUSTOM_1_2_1",
            title: "Урьдчилсан төлбөрт"
          }, {
            type: "postback",
            title: "Shake & Share",
            payload: "CUSTOM_1_2_2"
          }, {
            type: "postback",
            title: "Нэмэлт үйлчилгээ",
            payload: "CUSTOM_1_2_3"
          }]
        }
      }
    }
  };  
  callSendAPI(messageData);
}





function CUSTOM_1_2_2(recipientId) {
    
   var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "button",
          text: "Shake and Share",
          buttons:[{
            type: "postback",
            payload: "CUSTOM_1_2_2_1",
            title: "Танилцуулга"
          }, {
            type: "postback",
            title: "Бүртгүүлэх заавар",
            payload: "CUSTOM_1_2_2_2"
          }, {
            type: "postback",
            title: "Үйлчилгээ ашиглах",
            payload: "CUSTOM_1_2_2_3"
          }]
        }
      }
    }
  };  
  callSendAPI(messageData);
}
function CUSTOM_1_3(recipientId) {
    
   var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "button",
          text: "Дата",
          buttons:[{
            type: "postback",
            payload: "CUSTOM_1_3_1",
            title: "Дата багц"
          }, {
            type: "postback",
            title: "Facebook",
            payload: "CUSTOM_1_3_2"
          }]
        }
      }
    }
  };  
  callSendAPI(messageData);
}

function CUSTOM_1_1_1(recipientId) {
    
   var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "button",
          text: "Дараах цэснээс сонгоно уу",
          buttons:[{
            type: "postback",
            payload: "CUSTOM_1_1_1_1",
            title: "Төлбөр шалгах заавар"
          }, {
            type: "postback",
            title: "Mobile,интернэт банк",
            payload: "CUSTOM_1_1_1_2"
          }, {
            type: "postback",
            title: "Цахим салбар",
            payload: "CUSTOM_1_1_1_3"
          }]
        }
      }
    }
  };  
  callSendAPI(messageData);
}
function CUSTOM_1_1_2(recipientId) {
    
   var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "button",
          text: "Дараах цэснээс сонгоно уу",
          buttons:[{
            type: "postback",
            payload: "CUSTOM_1_1_2_1",
            title: "Дугаарын үнэ тариф"
          }, {
            type: "postback",
            title: "Багцын танилцуулга",
            payload: "CUSTOM_1_1_2_2"
          }, {
            type: "postback",
            title: "Онцлог давуу тал",
            payload: "CUSTOM_1_1_2_3"
          }]
        }
      }
    }
  };  
  callSendAPI(messageData);
}
function CUSTOM_1_1_3(recipientId) {
 var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "button",
          text: "Нэмэлт үйлчилгээ",
          buttons:[
                {
                              "type": "web_url",
                              "url": "https://www.skytel.mn/p/extra", 
                              "title": "Энд дарна уу"
                            }
          ]
        }
      }
    }
  };  

  callSendAPI(messageData);
}
function CUSTOM_1_2_3(recipientId) {
 var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "button",
          text: "Нэмэлт үйлчилгээ",
          buttons:[
                {
                              "type": "web_url",
                              "url": "https://www.skytel.mn/p/extra", 
                              "title": "Энд дарна уу"
                            }
          ]
        }
      }
    }
  };  

  callSendAPI(messageData);
}
function CUSTOM_3(recipientId) {
    
   var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "button",
          text: "Дараах цэснээс сонгоно уу",
          buttons:[{
            type: "postback",
            payload: "CUSTOM_3_1_1",
            title: "Гар утасны үнэ тариф"
          }, {
            type: "postback",
            title: "Модем",
            payload: "CUSTOM_3_2"
          }, {
            type: "postback",
            title: "Тохиргоо ",
            payload: "CUSTOM_3_3"
          }]
        }
      }
    }
  };  
  callSendAPI(messageData);
}



function salbarMessage(recipientId) {
    
   var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "button",
          text: "Салбар",
          buttons:[{
            type: "postback",
            payload: "CUSTOM_salbarub",
            title: "Улаанбаатар хот"
          }, {
            type: "postback",
            title: "Орон нутаг ",
            payload: "CUSTOM_salbaroron"
          }]
        }
      }
    }
  };  
  callSendAPI(messageData);
}
function CUSTOM_salbar_2(recipientId) {
 var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "button",
          text: "Салбар",
          buttons:[{
            type: "postback",
            payload: "CUSTOM_salbarub",
            title: "Улаанбаатар хот"
          }, {
            type: "postback",
            title: "Орон нутаг ",
            payload: "CUSTOM_salbaroron"
          }]
        }
      }
    }
  };  
  callSendAPI(messageData);
}

function CUSTOM_salbarub(recipientId) {
    networking.getLatestNews((detail) => {
      newsDetail = detail; 
      var messageData = {
        recipient: {
          id: recipientId
        },
        message: {
          attachment: {
            type: "template",
            payload: {
              template_type: "generic",
              elements: [{
                title: "Төв Плаза*СБДүүрэг, Чингисийн өргөн чөлөө-9, Скайтел Плаза* 7611-2000 ",
                image_url: `https://www.skytel.mn/app/images/messenger-bot/branches/3.jpg`,
                subtitle: "Даваа-Баасан: 08:30-18:00 Бямба,Ням: 10:00-18:00",
                item_url: `https://www.skytel.mn/content/branches/Ulaanbaatar`,               
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              },{
                 title: "Залуус салбар СБДүүрэг, Мэдээлэл технологийн үндэсний паркын 1 давхар 7611-2005 ",
                image_url: `https://www.skytel.mn/app/images/messenger-bot/branches/6.jpg`,
                subtitle: "* Даваа-Баасан: 09:00-20:00 Бямба,Ням: 10:00-20:00",
                item_url: `https://www.skytel.mn/content/branches/Ulaanbaatar`,               
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              },{
               title: "ӨНӨР салбар*СХДүүрэг, 1-р хороолол, Голомт банкны байр* 7611-2002",
                image_url: `https://www.skytel.mn/app/images/messenger-bot/branches/7.jpg`,
                subtitle: "Даваа-Баасан: 09:00-20:00 Бямба,Ням: 10:00-18:00",
                item_url: `https://www.skytel.mn/content/branches/Ulaanbaatar`,               
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              },{
                 title: "Скайтел үйлчилгээний төв ЧДүүрэг, 3-р хороо 7611-2001",
                image_url: `https://www.skytel.mn/app/images/messenger-bot/branches/5.jpg`,
                subtitle: "Даваа-Баасан: 08:30-18:00 Бямба,Ням: 10:00-19:00",
                item_url: `https://www.skytel.mn/content/branches/Ulaanbaatar`,               
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              },{
                 title: "Энх тайвны өргөн чөлөө-25 Улсын их дэлгүүр 5-р давхар 7611-2010",
                image_url: `https://www.skytel.mn/app/images/messenger-bot/branches/8.jpg`,
                subtitle: "Даваа-Баасан: 09:00-21:30 Бямба,Ням: 09:30-21:30",
                item_url: `https://www.skytel.mn/content/branches/Ulaanbaatar`,               
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              },{
                 title: "ОРГИЛ салбар ХУДүүрэг, Зайсан, Оргил худалдааны төвийн 1 давхар 7611-2009",
                image_url: `https://www.skytel.mn/app/images/messenger-bot/branches/2.jpg`,
                subtitle: "Даваа-Баасан: 10:00-20:00 Бямба,Ням: 10:00-19:00",
                item_url: `https://www.skytel.mn/content/branches/Ulaanbaatar`,               
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              },{
                 title: "САНСАР салбар БЗДүүрэг, 15 хороолол, Сансарын Начин заан байранд 76112006",
                image_url: `https://www.skytel.mn/app/images/messenger-bot/branches/4.jpg`,
                subtitle: "Даваа-Баасан: 09:00-19:00 Бямба,Ням: 10:00-18:00",
                item_url: `https://www.skytel.mn/content/branches/Ulaanbaatar`,               
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              },{
                 title: "Имарт салбар*Баянзүрх дүүрэг, Технологийн гудамж, Имарт Чингис салбар 2 давхар",
                image_url: `https://www.skytel.mn/app/images/messenger-bot/branches/1.jpg`,
                subtitle: "Даваа-Ням: 10:00-22:00",
                item_url: `https://www.skytel.mn/content/branches/Ulaanbaatar`,               
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              },{
                 title: "Налайх дүүрэг, 2-р хороо, МХС ТӨК байр, 1-р давхар, Налайх салбар 7611-2003",
                image_url: `https://www.skytel.mn/app/images/messenger-bot/branches/9.jpg`,
                subtitle: "Даваа-Баасан: 09:00-19:00 Бямба: 11:00-16:00 Ням:Амарна",
                item_url: `https://www.skytel.mn/content/branches/Ulaanbaatar`,               
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              }]
            }
          }
        }
      };  

      callSendAPI(messageData);
  });
  

  }
           

function CUSTOM_salbaroron_tuv(recipientId) {
    networking.getLatestNews((detail) => {
      newsDetail = detail; 
      var messageData = {
        recipient: {
          id: recipientId
        },
        message: {
          attachment: {
            type: "template",
            payload: {
              template_type: "generic",
              elements: [{
                title: "Сэлэнгэ аймаг, Сайхан сум, 1-р баг, 9-р байр2-0 тоот 9604-0033",
                image_url: `https://www.skytel.mn/app/images/download/SKYtel_logo_transparent.png`,
                subtitle: "Даваа-Баасан: 10:00-18:00 Бямба: 11:00-16:00 Ням: амарна",
                item_url: `https://www.skytel.mn/content/branches/Ulaanbaatar`,               
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              },{
                 title: "Сэлэнгэ аймаг, 2-р баг, Сэлэнгэ Плаза 9110-2043",
                image_url: `https://www.skytel.mn/app/images/download/SKYtel_logo_transparent.png`,
                subtitle: "Даваа-Баасан: 09:00-19:00 Бямба: 11:00-16:00 Ням: амарна ",
                item_url: `https://www.skytel.mn/content/branches/Ulaanbaatar`,               
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              },{
               title: "Сэлэнгэ аймаг, Мандал сум, 3-р баг, Буян тахь ХХК-ийн байр 9110-1235",
                image_url: `https://www.skytel.mn/app/images/download/SKYtel_logo_transparent.png`,
                subtitle: "Даваа-Баасан: 09:00-19:00 Бямба: 11:00-16:00 Ням:амарна",
                item_url: `https://www.skytel.mn/content/branches/Ulaanbaatar`,               
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              },{
                 title: "Сэлэнгэ аймаг, Алтанбулаг сум, Бүргэдэй 1-р баг, Булаг 2-17 9008-4949",
                image_url: `https://www.skytel.mn/app/images/download/SKYtel_logo_transparent.png`,
                subtitle: "Даваа-Баасан: 09:00-18:00 Бямба: 11:00-15:00 Ням: амарна",
                item_url: `https://www.skytel.mn/content/branches/Ulaanbaatar`,               
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              },{
                 title: "Дархан-Уул аймаг, 14-р баг, Эрдэнэс Плаза 1-р давхар 9110-1223",
                image_url: `https://www.skytel.mn/app/images/download/SKYtel_logo_transparent.png`,
                subtitle: "Даваа-Баасан: 09:00-20:00 Бямба, Ням: 10:00-18:00",
                item_url: `https://www.skytel.mn/content/branches/Ulaanbaatar`,               
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              },{
                 title: "Өмнөговь аймаг, 3-р баг, МАН-ын байр 1 давхар 9110-1608",
                image_url: `https://www.skytel.mn/app/images/download/SKYtel_logo_transparent.png`,
                subtitle: "Даваа-Баасан: 09:00-19:00 Бямба, Ням: 11:00-16:00",
                item_url: `https://www.skytel.mn/content/branches/Ulaanbaatar`,               
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              },{
                 title: "Орхон аймаг, Хүрэнбулаг баг, Анса трейд ХХК-ийн байр 1-р давхар 9111-8169",
                image_url: `https://www.skytel.mn/app/images/download/SKYtel_logo_transparent.png`,
                subtitle: "Даваа-Баасан: 09:00-20:00 Бямба, Ням: 10:00-18:00",
                item_url: `https://www.skytel.mn/content/branches/Ulaanbaatar`,               
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              },{
                 title: "Булган аймаг, 5-р баг, Тулга төв 9110-1217",
                image_url: `https://www.skytel.mn/app/images/download/SKYtel_logo_transparent.png`,
                subtitle: "Даваа-Баасан: 09:00-19:00 Бямба: 11:00-16:00 Ням: амарна",
                item_url: `https://www.skytel.mn/content/branches/Ulaanbaatar`,               
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              },{
                 title: "Дорноговь аймаг, 1-р баг, Зорчигч үйлчилгээний төв 9110-1564",
                image_url: `https://www.skytel.mn/app/images/download/SKYtel_logo_transparent.png`,
                subtitle: "Даваа-Баасан: 08:00-18:00 Бямба: 12:00-18:00 Ням: амарна",
                item_url: `https://www.skytel.mn/content/branches/Ulaanbaatar`,               
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              },{
                 title: "Дорноговь аймаг, 1-р баг, сумын тамгын газрын зүүн талд 9110-1233",
                image_url: `https://www.skytel.mn/app/images/download/SKYtel_logo_transparent.png`,
                subtitle: "Даваа-Баасан: 09:00-19:00 Бямба, Ням: 11:00-16:00",
                item_url: `https://www.skytel.mn/content/branches/Ulaanbaatar`,               
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              }]
            }
          }
        }
      };  

      callSendAPI(messageData);
  });
  

  }
  function CUSTOM_2_3_2(recipientId) {
    networking.getLatestNews((detail) => {
      newsDetail = detail; 
      var messageData = {
        recipient: {
          id: recipientId
        },
        message: {
          attachment: {
            type: "template",
            payload: {
              template_type: "generic",
              elements: [{
                title: "Админ дугаараас гишүүн бүртгэх хүсэлт илгээх",
                image_url: `https://www.skytel.mn/uploads/images/1(8).jpg`,
                subtitle: "Түлхүүр үг:+9*******Тусгай дугаар: 555",
                            
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              },{
                 title: "Гэрээний дугаар харах",
                image_url: `https://www.skytel.mn/uploads/images/1(8).jpg`,
                subtitle: " Түлхүүр үг: Geree Тусгай дугаар: 555",
                         
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              },{
               title: "Бүртгэлтэй гишүүн дугааруудын жагсаалт харах",
                image_url: `https://www.skytel.mn/uploads/images/1(8).jpg`,
                subtitle: "Түлхүүр үг: ALLТусгай дугаар: 555",
                            
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              },{
                 title: "Гишүүн дугаар хасах",
                image_url: `https://www.skytel.mn/uploads/images/1(8).jpg`,
                subtitle: "Түлхүүр үг: -9*******Тусгай дугаар: 555",
                        
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              },{
                 title: "Дата үлдэгдэл шалгах",
                image_url: `https://www.skytel.mn/uploads/images/1(8).jpg`,
                subtitle: "Түлхүүр үг: DATA Тусгай дугаар: 555",
                            
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              },{
                 title: "Гишүүн дугаар группт нэмэх хүсэлт хүлээн авах",
                image_url: `https://www.skytel.mn/uploads/images/1(8).jpg`,
                subtitle: "Түлхүүр үг: OK Тусгай дугаар: 555",
                         
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              },]
            }
          }
        }
      };  

      callSendAPI(messageData);
  });
  

  }                       
                         
                         
function CUSTOM_salbaroron_zuun(recipientId) {
    networking.getLatestNews((detail) => {
      newsDetail = detail; 
      var messageData = {
        recipient: {
          id: recipientId
        },
        message: {
          attachment: {
            type: "template",
            payload: {
              template_type: "generic",
              elements: [{
                title: "Сүхбаатар аймаг, 7-р баг, АН-н байр 9110-1578",
                image_url: `https://www.skytel.mn/app/images/download/SKYtel_logo_transparent.png`,
                subtitle: "Даваа-Баасан: 09:00-19:00 Бямба: 11:00-16:00 Ням: амарна",
                item_url: `https://www.skytel.mn/content/branches/Ulaanbaatar`,               
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              },{
                 title: "Дорнод аймаг, 61-р байшин 9110-0229",
                image_url: `https://www.skytel.mn/app/images/download/SKYtel_logo_transparent.png`,
                subtitle: "Даваа-Баасан: 09:00-19:00 Бямба: 11:00-16:00 Ням:амарна ",
                item_url: `https://www.skytel.mn/content/branches/Ulaanbaatar`,               
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              },{
               title: "Хэнтий аймаг, 3-р баг, Алагбарс ХХК байр 9111-8322",
                image_url: `https://www.skytel.mn/app/images/download/SKYtel_logo_transparent.png`,
                subtitle: "Даваа-Баасан: 09:00-19:00 Бямба: 11:00-16:00 Ням: амарна",
                item_url: `https://www.skytel.mn/content/branches/Ulaanbaatar`,               
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              },{
                 title: "Улаанбаатар, Багануур дүүрэг, Холбооны байр 9111-4120",
                image_url: `https://www.skytel.mn/app/images/download/SKYtel_logo_transparent.png`,
                subtitle: "Даваа-Баасан: 09:00-19:00 Бямба: 11:00-16:00 Ням:амарна",
                item_url: `https://www.skytel.mn/content/branches/Ulaanbaatar`,               
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              },{
                 title: "Төв аймаг Зуунмод сум,1-р баг холбооны байр9110-1318",
                image_url: `https://www.skytel.mn/app/images/download/SKYtel_logo_transparent.png`,
                subtitle: "Даваа-Баасан: 09:00-19:00 Бямба: 11:00-16:00 Ням: амарна",
                item_url: `https://www.skytel.mn/content/branches/Ulaanbaatar`,               
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              },{
                 title: "Говьсүмбэр аймаг 1-р баг, МАН-н байрны 1-р давхар 9110-1564",
                image_url: `https://www.skytel.mn/app/images/download/SKYtel_logo_transparent.png`,
                subtitle: "Даваа-Баасан: 09:00-19:00 Бямба: 11:00-16:00 Ням: амарна",
                item_url: `https://www.skytel.mn/content/branches/Ulaanbaatar`,               
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              },{
                 title: "Дорноговь аймаг, 3-р баг, Шанти цогцолбор 2-р давхар 9110-1215",
                image_url: `https://www.skytel.mn/app/images/download/SKYtel_logo_transparent.png`,
                subtitle: "Даваа-Баасан: 09:00-19:00 Бямба, Ням: 11:00-16:00",
                item_url: `https://www.skytel.mn/content/branches/Ulaanbaatar`,               
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              },{
                 title: "Дундговь аймаг, 7-р баг, Гандалай ХТ 9110-1228",
                image_url: `https://www.skytel.mn/app/images/download/SKYtel_logo_transparent.png`,
                subtitle: "Даваа-Баасан: 09:00-19:00 Бямба: 11:00-16:00 Ням: амарна",
                item_url: `https://www.skytel.mn/content/branches/Ulaanbaatar`,               
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              },{
                 title: "Дархан-Уул аймаг, дархан сум, Алтансагс төвийн 1-р давхар 9110-1434",
                image_url: `https://www.skytel.mn/app/images/download/SKYtel_logo_transparent.png`,
                subtitle: "Даваа-Баасан: 10:00-18:00 Бямба: 10:00-17:00 Ням: амарна",
                item_url: `https://www.skytel.mn/content/branches/Ulaanbaatar`,               
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              },{
                 title: "Хөвсгөл аймаг, Тариалан сум, 1-р баг Шивэртийн 4-4 тоот 9110-1247",
                image_url: `https://www.skytel.mn/app/images/download/SKYtel_logo_transparent.png`,
                subtitle: "Даваа-Баасан: 10:00-18:00 Бямба: 11:00-16:00 Ням: амарна",
                item_url: `https://www.skytel.mn/content/branches/Ulaanbaatar`,               
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              }]
            }
          }
        }
      };  

      callSendAPI(messageData);
  });
  

  }

function CUSTOM_salbaroron_baruun(recipientId) {
    networking.getLatestNews((detail) => {
      newsDetail = detail; 
      var messageData = {
        recipient: {
          id: recipientId
        },
        message: {
          attachment: {
            type: "template",
            payload: {
              template_type: "generic",
              elements: [{
                title: "Баян-Өлгий аймаг, 5-р баг, МХС ТӨК-н байр1-р давхар  9110-1204",
                image_url: `https://www.skytel.mn/app/images/download/SKYtel_logo_transparent.png`,
                subtitle: "Даваа-Баасан: 08:00-18:00 Бямба: 11:00-16:00 Ням: амарна",
                item_url: `https://www.skytel.mn/content/branches/Ulaanbaatar`,               
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              },{
                 title: "Увс аймаг, 3-р баг, Бэлбулаг төв 1-р давхар 9110-1251",
                image_url: `https://www.skytel.mn/app/images/download/SKYtel_logo_transparent.png`,
                subtitle: "Даваа-Баасан: 08:00-18:00 Бямба, Ням: 11:00-16:00 ",
                item_url: `https://www.skytel.mn/content/branches/Ulaanbaatar`,               
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              },{
                title: "Ховд аймаг, 1-р баг, Алагтолгой баг, сонголт төв 9110-1255",
                image_url: `https://www.skytel.mn/app/images/download/SKYtel_logo_transparent.png`,
                subtitle: "Даваа-Баасан: 08:00-18:00 Бямба: 11:00-16:00 Ням: амарна",
                item_url: `https://www.skytel.mn/content/branches/Ulaanbaatar`,               
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              },{
                 title: "Завхан аймаг, Улиастай сум, Жинст баг 9110-1231",
                image_url: `https://www.skytel.mn/app/images/download/SKYtel_logo_transparent.png`,
                subtitle: "Даваа-Баасан: 09:00-19:00 Бямба: 11:00-16:00 Ням: амарна",
                item_url: `https://www.skytel.mn/content/branches/Ulaanbaatar`,               
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              },{
                 title: "Говь-алтай аймаг, Есөнбулаг сум, Оргил баг, Төрийн банкны байр 9110-1219",
                image_url: `https://www.skytel.mn/app/images/download/SKYtel_logo_transparent.png`,
                subtitle: "Даваа-Баасан: 09:00-19:00 Бямба: 11:00-16:00 Ням: амарна",
                item_url: `https://www.skytel.mn/content/branches/Ulaanbaatar`,               
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              },{
                 title: "Завхан аймаг, Тосонцэнгэл сум, Дархан-Уул баг, 4-63 тоот 9110-1248",
                image_url: `https://www.skytel.mn/app/images/download/SKYtel_logo_transparent.png`,
                subtitle: "Даваа-Баасан: 10:00-18:00 Бямба: 11:00-16:00 Ням: амарна",
                item_url: `https://www.skytel.mn/content/branches/Ulaanbaatar`,               
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              },{
                 title: "Баянхонгор аймаг, Баянхонгор сум, Номгон 1-баг, ОҮ-14 9110-1662",
                image_url: `https://www.skytel.mn/app/images/download/SKYtel_logo_transparent.png`,
                subtitle: "Даваа-Баасан: 09:00-19:00 Бямба, Ням: 11:00-16:00",
                item_url: `https://www.skytel.mn/content/branches/Ulaanbaatar`,               
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              },{
                 title: "Хөвсгөл аймаг, 8-р баг 13 байрны 1 тоот 9110-1513",
                image_url: `https://www.skytel.mn/app/images/download/SKYtel_logo_transparent.png`,
                subtitle: "Даваа-Баасан: 09:00-19:00 Бямба,Ням: 11:00-16:00",
                item_url: `https://www.skytel.mn/content/branches/Ulaanbaatar`,               
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              },{
                 title: "Архангай аймаг, Эрдэнэбулган сум, 1-р баг, Холбооны байр 9110-1130",
                image_url: `https://www.skytel.mn/app/images/download/SKYtel_logo_transparent.png`,
                subtitle: "Даваа-Баасан: 09:00-19:00 Бямба: 11:00-16:00 ням: амарна",
                item_url: `https://www.skytel.mn/content/branches/Ulaanbaatar`,               
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              },{
                 title: "Өвөрхангай аймаг, 5-р баг, Элит орон сууц 1 давхар 9110-1568",
                image_url: `https://www.skytel.mn/app/images/download/SKYtel_logo_transparent.png`,
                subtitle: "Даваа-Баасан: 09:00-19:00 Бямба, Ням: 10:00-16:00",
                item_url: `https://www.skytel.mn/content/branches/Ulaanbaatar`,               
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              }]
            }
          }
        }
      };  

      callSendAPI(messageData);
  });
  

  }
function CUSTOM_salbaroron(recipientId) {
    
   var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "button",
          text: "Дараах цэснээс сонгоно уу",
          buttons:[{
            type: "postback",
            payload: "CUSTOM_salbaroron_tuv",
            title: "Төвийн бүс"
          }, {
            type: "postback",
            title: "Зүүн бүс",
            payload: "CUSTOM_salbaroron_zuun"
          }, {
            type: "postback",
            title: "Баруун бүс ",
            payload: "CUSTOM_salbaroron_baruun"
          }]
        }
      }
    }
  };  
  callSendAPI(messageData);
}
function CUSTOM_3_1(recipientId) {
 var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "button",
          text: "Гар утасны үнэ тариф",
          buttons:[
                {
                              "type": "web_url",
                              "url": "https://www.skytel.mn/shop/product", 
                              "title": "Энд дарна уу"
                            }
          ]
        }
      }
    }
  };  

  callSendAPI(messageData);
}
function CUSTOM_3_2(recipientId) {
    
   var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "button",
          text: "Дараах цэснээс сонгоно уу",
          buttons:[{
            type: "postback",
            payload: "CUSTOM_3_2_1",
            title: "Дата үлдэгдэл шалгах"
          }, {
            type: "postback",
            title: "Цэнэглэх заавар",
            payload: "CUSTOM_3_2_2"
          }]
        }
      }
    }
  };  
  callSendAPI(messageData);
}
function CUSTOM_3_2_2(recipientId) {
    networking.getLatestNews((detail) => {
      newsDetail = detail; 
      var messageData = {
        recipient: {
          id: recipientId
        },
        message: {
          attachment: {
            type: "template",
            payload: {
              template_type: "generic",
              elements: [{
                title: "Та дараах дата багцуудаас сонголтоо хийж модемоо цэнэглэнэ үү",
                image_url: `https://www.skytel.mn/app/images/messenger-bot/guys.png`,
                subtitle: "1GB 30 хоног 10000₮",
                buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              },{
                   title: "Та дараах дата багцуудаас сонголтоо хийж модемоо цэнэглэнэ үү",
                image_url: `https://www.skytel.mn/app/images/messenger-bot/guys.png`,
                subtitle: "2GB 30 хоног 13000₮",
                           
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              },{
              title: "Та дараах дата багцуудаас сонголтоо хийж модемоо цэнэглэнэ үү",
                image_url: `https://www.skytel.mn/app/images/messenger-bot/guys.png`,
                subtitle: "3GB 30 хоног 15000₮",
                       
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              },{
            title: "Та дараах дата багцуудаас сонголтоо хийж модемоо цэнэглэнэ үү",
                image_url: `https://www.skytel.mn/app/images/messenger-bot/guys.png`,
                subtitle: "5GB 30 хоног 20000₮",
                     
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              },{
                 title: "Та дараах дата багцуудаас сонголтоо хийж модемоо цэнэглэнэ үү",
                image_url: `https://www.skytel.mn/app/images/messenger-bot/guys.png`,
                subtitle: "10GB 60 хоног 30000₮",
                             
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              },{
                   title: "Та дараах дата багцуудаас сонголтоо хийж модемоо цэнэглэнэ үү",
                image_url: `https://www.skytel.mn/app/images/messenger-bot/guys.png`,
                subtitle: "20GB 90 хоног 50000₮",
                             
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              }]
            }
          }
        }
      };  

      callSendAPI(messageData);
  });
  

  }
function CUSTOM_3_3(recipientId) {
    
   var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "button",
          text: "Гар утасны тохиргоо",
          buttons:[{
            type: "postback",
            payload: "CUSTOM_3_3_1",
            title: "Интернет тохиргоо"
          }, {
            type: "postback",
            title: "Сүлжээний тохиргоо",
            payload: "CUSTOM_3_3_2"
          }]
        }
      }
    }
  };  
  callSendAPI(messageData);
}
function CUSTOM_3_3_1(recipientId) {
    
   var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "button",
          text: "Гар утасны тохиргоо",
          buttons:[{
            type: "postback",
            payload: "CUSTOM_3_3_1_1",
            title: "Android"
          }, {
            type: "postback",
            title: "IOS",
            payload: "CUSTOM_3_3_1_2"
          }]
        }
      }
    }
  };  
  callSendAPI(messageData);
}
function CUSTOM_3_3_2(recipientId) {
    
   var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "button",
          text: "Гар утасны тохиргоо",
          buttons:[{
            type: "postback",
            payload: "CUSTOM_3_3_2_1",
            title: "Android"
          }, {
            type: "postback",
            title: "IOS",
            payload: "CUSTOM_3_3_2_2"
          }]
        }
      }
    }
  };  
  callSendAPI(messageData);
}


function CUSTOM_3_2_1(recipientId) {
 var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "button",
          text: "Та 1515 лавлах төв, эсвэл online ажилтантай холбогдоно уу.",
          buttons:[
                {
                              "type": "web_url",
                              "url": "https://www.skytel.mn/", 
                              "title": "Энд дарна уу"
                            }
          ]
        }
      }
    }
  };  

  callSendAPI(messageData);
}


function CUSTOM_1_1_1_2(recipientId) {
 var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "button",
          text: "Та интэрнэт банк болон гар утасны application ашиглан төлбөрөө төлөх боломжтой. Гүйлгээний утга алдаагүй зөв тохиолдолд үйлчилгээний эрх 10 минутын дотор нээгдэнэ.Та доорх холбоосоор хандан дэлгэрэнгүй заавар авна уу.",
          buttons:[
                {
                              "type": "web_url",
                              "url": "https://www.skytel.mn/p/postpaid-info", 
                              "title": "Энд дарна уу"
                            }
          ]
        }
      }
    }
  };  

  callSendAPI(messageData);
}

function CUSTOM_1_2_2_1(recipientId) {
 var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "button",
          text: "14-22 насны хэрэглэгч Shake&share үйлчилгээнд хамрагдах боломжтой. 23 нас хүртлээ сар бүр 100MB дата, ойр дотны 3 дугаартаа сар бүр 100МB бэлэглэх, мөн бэлэглэх бүртээ 100МВ датаг урамшуулалд авна.  Мөн Та төрсөн өдрөөрөө 1000000 нэгжийн бэлэгтэй. Үүнээс гадна Shake&share-д бүртгэлтэй 1 дугаартай 1 төгрөгөөр дуудлага хийх боломжтойгоос гадна Skytel аппликейшн татаж аваад дугаараа оруулаад сэгсрээд дататай болно.",
          buttons:[
                {
                              "type": "web_url",
                              "url": "https://www.skytel.mn/content/2368/view", 
                              "title": "Энд дарна уу"
                            }
          ]
        }
      }
    }
  };  

  callSendAPI(messageData);
}
function CUSTOM_3_1_1(recipientId) {
 var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "button",
          text: "Үнэ тарифын мэдээлэл",
          buttons:[
                {
                              "type": "web_url",
                              "url": "https://www.skytel.mn/shop/product", 
                              "title": "Энд дарна уу"
                            }
          ]
        }
      }
    }
  };  

  callSendAPI(messageData);
}


function CUSTOM_1_2_2_3(recipientId) {
    networking.getLatestNews((detail) => {
      newsDetail = detail; 
      var messageData = {
        recipient: {
          id: recipientId
        },
        message: {
          attachment: {
            type: "template",
            payload: {
              template_type: "generic",
              elements: [{
                title: "Хосын дугаар бүртгэх Түлхүүр үг: 9******* Тусгай дугаар 123",
                image_url: `https://www.skytel.mn/uploads/images/5(1).png`,
                subtitle: "Хосын дугаар цуцлах: Single Тусгай дугаар: 123",
                         
                buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              },{
                 title: "Data share: Түлхүүр үг:9xxxxxxx 100MB  Тусгай дугаар: 123",
                image_url: `https://www.skytel.mn/uploads/images/5(1).png`,
                subtitle: "Дата хэрэглээгээ шалгах Түлхүүр үг: Data  Тусгай дугаар: 123",
              
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              },{
               title: "Төрсөн өдрийн урамшуулал шалгах: Түлхүүр үг: Bday Тусгай дугаар: 123",
                image_url: `https://www.skytel.mn/uploads/images/6(1).png`,
                subtitle: " ",
                   
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              }]
            }
          }
        }
      };  

      callSendAPI(messageData);
  });
  

  }

function CUSTOM_1_3_1(recipientId) {
    networking.getLatestNews((detail) => {
      newsDetail = detail; 
      var messageData = {
        recipient: {
          id: recipientId
        },
        message: {
          attachment: {
            type: "template",
            payload: {
              template_type: "generic",
              elements: [{
                 title: "100MB 10 хоног Үнэ:1000",
                image_url: `https://www.skytel.mn/app/images/messenger-bot/data_package.png`,
                subtitle: "Идэвхжүүлэх заавар:100mb send 123",
              
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              },{
               title: "300MB 15 хоног Үнэ:3000",
                image_url: `https://www.skytel.mn/app/images/messenger-bot/data_package.png`,
                subtitle: "Идэвхжүүлэх заавар:300mb send 123",
                   
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              },{
                 title: "1GB 30 хоног Үнэ:10000",
                image_url: `https://www.skytel.mn/app/images/messenger-bot/data_package.png`,
                subtitle: "Идэвхжүүлэх заавар:1GB  send 123",
                             
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              },{
                 title: "2GB 30 хоног Үнэ:13000",
                image_url: `https://www.skytel.mn/app/images/messenger-bot/data_package.png`,
                subtitle: "Идэвхжүүлэх заавар:2GB send 123",
                           
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              },{
                 title: "10 GB 60 хоног Үнэ:30000",
                image_url: `https://www.skytel.mn/app/images/messenger-bot/data_package.png`,
                subtitle: "Идэвхжүүлэх заавар:10GB send 123",
                
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
             },{
                 title: "1GB+247 багц Хугацаа:48 цаг Үнэ:2000₮",
                image_url: `https://www.skytel.mn/app/images/messenger-bot/data_package.png`,
                subtitle: "Идэвхжүүлэх заавар: 2 send 123",
                
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
             }]
            }
          }
        }
      };  

      callSendAPI(messageData);
  });
  

  }

function CUSTOM_1_3_2(recipientId) {
    networking.getLatestNews((detail) => {
      newsDetail = detail; 
      var messageData = {
        recipient: {
          id: recipientId
        },
        message: {
          attachment: {
            type: "template",
            payload: {
              template_type: "generic",
              elements: [{
                 title: "Facebook багц 30 хоног Үнэ:5000",
                image_url: `https://www.skytel.mn/app/images/messenger-bot/fb_package.png`,
                subtitle: "Идэвхжүүлэх заавар:Facebook send 123",
              
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              },{
               title: "Facebook+247 багц",
                image_url: `https://www.skytel.mn/app/images/messenger-bot/fb_package.png`,
                subtitle: "Хугацаа:24 цаг Үнэ:777₮  Идэвхжүүлэх заавар: 1 send 123",
                   
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              },{
                 title: "Facebook+247 багц ",
                image_url: `https://www.skytel.mn/app/images/messenger-bot/fb_package.png`,
                subtitle: "Хугацаа:24 цаг Үнэ:777₮  Идэвхжүүлэх заавар: 1 send 123",
                             
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              }]
            }
          }
        }
      };  

      callSendAPI(messageData);
  });
  


  }


function CUSTOM_1_1_2_1(recipientId) {
    networking.getLatestNews((detail) => {
      newsDetail = detail; 
      var messageData = {
        recipient: {
          id: recipientId
        },
        message: {
          attachment: {
            type: "template",
            payload: {
              template_type: "generic",
              elements: [{
                title: "Энгийн дугаар Үнэ:10000, Барьцаа(20000,50000)",
                image_url: `https://www.skytel.mn/app/images/beldsen/cover/postpaid_cover.jpg`,
                subtitle: "Үнэ цэнэтэй энгийн дугаар Үнэ:100000, Барьцаа(50000)",
                         
                buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              },{
                  title: "Азын дугаар Үнэ:60000, Барьцаа(20000,50000)",
                image_url: `https://www.skytel.mn/app/images/beldsen/cover/postpaid_cover.jpg`,
                subtitle: "Үнэ цэнэтэй азын дугаар Үнэ:200000, Барьцаа(50000)",
                   
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              },{
               title: "Алтан дугаар Үнэ:800000, Барьцаа(20000,50000)",
                image_url: `https://www.skytel.mn/app/images/beldsen/cover/postpaid_cover.jpg`,
                subtitle: "Үнэ цэнэтэй алтан дугаар Үнэ:800000, Барьцаа(50000)",
                           
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              }]
            }
          }
        }
      };  

      callSendAPI(messageData);
  });
  

  }




function CUSTOM_1_2_1(recipientId) {
    
   var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "button",
          text: "Урьдчилсан төлбөрт үйлчилгээ",
          buttons:[{
            type: "postback",
            payload: "Custom_middle_1",
            title: "Өнгөлөг дата"
          }, {
            type: "postback",
            title: "Өнгөлөг хоног",
            payload: "Custom_middle_2"
          }, {
            type: "postback",
            title: "Skyphone 3.0",
            payload: "Custom_middle_3"
          }]
        }
      }
    }
  };  
  callSendAPI(messageData);
}
function CUSTOM_1_1_2_2(recipientId) {
    networking.getLatestNews((detail) => {
      newsDetail = detail; 
      var messageData = {
        recipient: {
          id: recipientId
        },
        message: {
          attachment: {
            type: "template",
            payload: {
              template_type: "generic",
              elements: [{
                title: "10,000₮",
                image_url: `https://www.skytel.mn/app/images/beldsen/individual/postpaid-10k.png`,
                subtitle: "Яриа:250мин, Дата:200MB, Суурь хураамж:10,000₮",
                         
                buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              },{
           title: "20,000₮",
                image_url: `https://www.skytel.mn/app/images/beldsen/individual/postpaid-20k.png`,
             subtitle: "Яриа:500мин, Дата:1GB, Мессэж:Хязгааргүй, Суурь хураамж:20,000₮",
                   
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              },{
               title: "40,000₮",
                image_url: `https://www.skytel.mn/app/images/beldsen/individual/postpaid-40k.png`,
                  subtitle: "Яриа:1000мин, Дата:4GB, Мессэж:Хязгааргүй, Суурь хураамж:40,000₮",
                           
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              },{
               title: "70,000₮",
                image_url: `https://www.skytel.mn/app/images/beldsen/individual/postpaid-70k.png`,
                  subtitle: "Яриа:2000мин, Дата:8GB, Мессэж:Хязгааргүй, Суурь хураамж:70,000₮",
                           
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              },{
               title: "100,000₮",
                image_url: `https://www.skytel.mn/app/images/beldsen/individual/postpaid-100k.png`,
                  subtitle: "Яриа:3000мин, Дата:12GB, Мессэж:Хязгааргүй, Суурь хураамж:100,000₮",
                           
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              }]
            }
          }
        }
      };  

      callSendAPI(messageData);
  });
   }

function CUSTOM_1_2_1_1(recipientId) {
  networking.getLatestNews((detail) => {
      newsDetail = detail; 
      var messageData = {
        recipient: {
          id: recipientId
        },
        message: {
          attachment: {
            type: "template",

            payload: {
              template_type: "generic",
                   image_aspect_ratio: "square",
                
              elements: [{
                title: "1000 карт",
                image_url: `http://www.skytel.mn:8080/uploads/products/201606/200/uploaded_a0e6334629accebab4e78569ab2da6640ebb69d6.png`,
                subtitle: "Хоног:1, Нэгж:1000",
                   
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              },{
              title: "2000 карт",
                image_url: `http://www.skytel.mn:8080/uploads/products/201606/200/uploaded_9a38a0807860d530143a6f5146f71b0670cb2974.png`,
               subtitle: "Хоног:3, Нэгж:1000, Дагалдах эрх:1024mb+Facebook",
                           
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              },{
                title: "3000 карт",
                image_url: `http://www.skytel.mn:8080/uploads/products/201606/200/uploaded_bf98815ac7832e96f94233039120012d1bfb0eb5.png`,
               subtitle: "Хоног:5, Нэгж:2000, Дагалдах эрх:1024mb+Facebook",
                           
            buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              },{
              title: "5000 карт",
                image_url: `http://www.skytel.mn:8080/uploads/products/201606/200/uploaded_eeec299743d691ae0c6567cd2e89329739e5f9e7.png`,
                 subtitle: "Хоног:15, Нэгж:2500, Дагалдах эрх:1024mb+Facebook",
                           
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              },{
             title: "247 карт",
                image_url: `http://www.skytel.mn:8080/uploads/products/201704/200/uploaded_c6888eb5268b0a1fec26930a09a444cf124e5bcc.png`,
             subtitle: "Хоног:30, Нэгж:5000, Дагалдах эрх:Сүлжээндээ үнэгүй",
                           
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              },{
           title: "10000 карт",
                image_url: `http://www.skytel.mn:8080/uploads/products/201606/200/uploaded_638cc78929de4f075374690bc67ac421b44ed4f4.png`,
          subtitle: "Хоног:30 , Нэгж:5000, Дагалдах эрх:1024mb+Facebook",
                           
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              },{
            title: "15000 карт",
                image_url: `http://www.skytel.mn:8080/uploads/products/201606/200/uploaded_78ea3d3d8dff80624be9db48d08de102981c400b.png`,
               subtitle: "Хоног:45, Нэгж:5000, Дагалдах эрх:1024mb+Facebook",
                           
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              },{
            title: "50000 карт",
                image_url: `http://www.skytel.mn:8080/uploads/products/201606/200/uploaded_90b396f63b8ab79433aa69d623fc0c467841bfd1.png`,
                subtitle: "Хоног:180, Нэгж:10000, Дагалдах эрх:5GB+Facebook",
                           
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              },{
            title: "90000 карт",
                image_url: `http://www.skytel.mn:8080/uploads/products/201606/200/uploaded_9bb3a85c1fbee834d24439f29bbc22ace90712f9.png`,
                subtitle: "Хоног:360, Нэгж:10000, Дагалдах эрх:15GB+Facebook",
                           
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              }]
            }
          }
        }
      };  

      callSendAPI(messageData);
  });
   }

function CUSTOM_1_2_1_2(recipientId) {
    networking.getLatestNews((detail) => {
      newsDetail = detail; 
      var messageData = {
        recipient: {
          id: recipientId
        },
        message: {
          attachment: {
            type: "template",
            payload: {
              template_type: "generic",
                   image_aspect_ratio: "square",
              elements: [{
                title: "500 карт",
                image_url: `https://www.skytel.mn/app/images/download/SKYtel_logo_transparent.png`,
                subtitle: " Нэгж:500, Үнэ: 500₮ ",
                         
                buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              },{
                title: "1000 карт",
                image_url: `http://www.skytel.mn:8080/uploads/products/201606/200/uploaded_a0e6334629accebab4e78569ab2da6640ebb69d6.png`,
                subtitle: "Хоног:5, Нэгж:1000, Үнэ: 1000₮ ",
                   
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              },{
              title: "2000 карт",
                image_url: `http://www.skytel.mn:8080/uploads/products/201606/200/uploaded_9a38a0807860d530143a6f5146f71b0670cb2974.png`,
                subtitle: "Хоног:20, Нэгж:2000, Үнэ: 2000₮ ",
                           
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              },{
                title: "3000 карт",
                image_url: `http://www.skytel.mn:8080/uploads/products/201606/200/uploaded_bf98815ac7832e96f94233039120012d1bfb0eb5.png`,
                subtitle: "Хоног:30, Нэгж:3000, Үнэ: 3000₮ ",
                           
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              },{
              title: "5000 карт",
                image_url: `http://www.skytel.mn:8080/uploads/products/201606/200/uploaded_eeec299743d691ae0c6567cd2e89329739e5f9e7.png`,
                subtitle: "Хоног:50, Нэгж:5000, Үнэ: 5000₮ ",
                           
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              },{
             title: "6000 карт",
                image_url: `http://www.skytel.mn:8080/uploads/products/201704/200/uploaded_03a3254fd07471e48093550a324782f317be4a72.png`,
                subtitle: "Хоног:60, Нэгж:6000, Үнэ: 6000₮ ",
                           
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              },{
           title: "10000 карт",
                image_url: `http://www.skytel.mn:8080/uploads/products/201606/200/uploaded_638cc78929de4f075374690bc67ac421b44ed4f4.png`,
                subtitle: "Хоног:100, Нэгж:10000, Үнэ: 10000₮ ",
                           
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              },{
            title: "15000 карт",
                image_url: `http://www.skytel.mn:8080/uploads/products/201606/200/uploaded_78ea3d3d8dff80624be9db48d08de102981c400b.png`,
                subtitle: "Хоног:150, Нэгж:15000, Үнэ: 15000₮ ",
                           
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              },{
            title: "50000 карт",
                image_url: `http://www.skytel.mn:8080/uploads/products/201606/200/uploaded_90b396f63b8ab79433aa69d623fc0c467841bfd1.png`,
                subtitle: "Хоног:180, Нэгж:50000, Үнэ: 50000₮ ",
                           
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              },{
            title: "90000 карт",
                image_url: `http://www.skytel.mn:8080/uploads/products/201606/200/uploaded_9bb3a85c1fbee834d24439f29bbc22ace90712f9.png`,
                subtitle: "Хоног:360, Нэгж:90000, Үнэ: 90000₮ ",
                           
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              }]
            }
          }
        }
      };  

      callSendAPI(messageData);
  });
   }

function CUSTOM_1_2_1_3(recipientId) {
    networking.getLatestNews((detail) => {
      newsDetail = detail; 
      var messageData = {
        recipient: {
          id: recipientId
        },
        message: {
          attachment: {
            type: "template",
            payload: {
              template_type: "generic",
                image_aspect_ratio: "square",
              elements: [{
                title: "500 карт",
                image_url: `https://www.skytel.mn/app/images/download/SKYtel_logo_transparent.png`,
                subtitle: "Нэгж:500, Үнэ: 500₮ ",
                         
                buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              },{
                title: "1000 карт",
                image_url: `http://www.skytel.mn:8080/uploads/products/201606/200/uploaded_a0e6334629accebab4e78569ab2da6640ebb69d6.png`,
                subtitle: "Хоног:2, Нэгж:1000, Үнэ: 1000₮ ",
                   
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              },{
              title: "2000 карт",
                image_url: `http://www.skytel.mn:8080/uploads/products/201606/200/uploaded_9a38a0807860d530143a6f5146f71b0670cb2974.png`,
                subtitle: "Хоног:5, Нэгж:2000, Үнэ: 2000₮ ",
                           
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              },{
                title: "3000 карт",
                image_url: `http://www.skytel.mn:8080/uploads/products/201606/200/uploaded_bf98815ac7832e96f94233039120012d1bfb0eb5.png`,
                subtitle: "Хоног:10, Нэгж:3000, Үнэ: 3000₮ ",
                           
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              },{
              title: "5000 карт",
                image_url: `http://www.skytel.mn:8080/uploads/products/201606/200/uploaded_eeec299743d691ae0c6567cd2e89329739e5f9e7.png`,
                subtitle: "Хоног:30, Нэгж:5000, Үнэ: 5000₮ ",
                           
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              },{
             title: "6000 карт",
                image_url: `http://www.skytel.mn:8080/uploads/products/201704/200/uploaded_03a3254fd07471e48093550a324782f317be4a72.png`,
                subtitle: "Хоног:30, Нэгж:6000, Үнэ: 6000₮ ",
                           
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              },{
           title: "10000 карт",
                image_url: `http://www.skytel.mn:8080/uploads/products/201606/200/uploaded_638cc78929de4f075374690bc67ac421b44ed4f4.png`,
                subtitle: "Хоног:30, Нэгж:10000, Үнэ: 10000₮ ",
                           
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              },{
            title: "15000 карт",
                image_url: `http://www.skytel.mn:8080/uploads/products/201606/200/uploaded_78ea3d3d8dff80624be9db48d08de102981c400b.png`,
                subtitle: "Хоног:45, Нэгж:15000, Үнэ: 15000₮ ",
                           
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              },{
            title: "50000 карт",
                image_url: `http://www.skytel.mn:8080/uploads/products/201606/200/uploaded_90b396f63b8ab79433aa69d623fc0c467841bfd1.png`,
                subtitle: "Хоног:180, Нэгж:50000, Үнэ: 50000₮ ",
                           
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              },{
            title: "90000 карт",
                image_url: `http://www.skytel.mn:8080/uploads/products/201606/200/uploaded_9bb3a85c1fbee834d24439f29bbc22ace90712f9.png`,
                subtitle: "Хоног:360, Нэгж:90000, Үнэ: 90000₮ ",
                           
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              }]
            }
          }
        }
      };  

      callSendAPI(messageData);
  });
   }



function maunfunc(recipientId) {
     var options = {
                method: 'GET',
                rejectUnauthorized: false,
                url: 'https://graph.facebook.com/v2.6/'+recipientId+'?fields=first_name,last_name&access_token=EAAM2wysYkZCABAM52M2b9j6ctpRZBmNTy0QByntDrwornV45SngAVAuifdIZC55RCIbeG27UMiVE5MBR8JaNKQ768W6a5lbAghZBOynWYpcxKoKrXhpt2gfHCj2dxju8wngZBU3ggRPyfWewfsEsIcoVxZAzcK0SrFHDH4MZAZAWOQZDZD',
                headers: {
                    "Content-Type": "application/json",
                    "Accept": "application/json"
                },
               
            };

            request(options, function (error, response, body) {
                
                console.log("Options:")
                console.log(options);

                if(!error){
                  console.log('Successfully connected to the FB info:', response && response.statusCode);
                  try{
                    if(response.statusCode == 200){
                      var resultObj = JSON.parse(body);
                         var messageData = {
    recipient: {
      id: recipientId
    },
    message: {

      text: 'Сайн байна уу? '+resultObj.first_name+' '+resultObj.last_name+'  СКАЙтел-н үйлчилгээний лавлахтай холбогдсон танд баярлалаа. СКАЙтел БОТ танд үйлчилж байна.' ,
      metadata: "ZOL_DEFINED_METADATA",
            
      quick_replies: [
        {
          "content_type":"text",
          "title":"Үндсэн хуудас",
          "payload":"CUSTOM_new"
        },
        {
          "content_type":"text",
          "title":"Салбар",
          "payload":"CUSTOM_salbar_2"
        },
          {
          "content_type":"text",
          "title":"Ажилтантай чатлах",
          "payload":"operator"
        },
        {
          "content_type":"text",
          "title":"Түлхүүр үг",
          "payload":"tulhuurug"
        }
        
      ]
            
    }
  };

  callSendAPI(messageData);

                    }else{
                        errorCallback(null, "Ямар нэг алдаа гарлаа! Алдааны код: "+response.statusCode); 
                    }

                  }catch(err){
                    errorCallback(err, "Дилерээс ирсэн хариуг боловсруулах үед алдаа гарлаа!"); 
                  }

                }else{
                    errorCallback(error, "Сервертэй холбогдох үед алдаа гарлаа!"); 
                }
          });
    
    
    
    
    

   }

function Custom_middle_1(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "button",
          text: "Өнгөлөг Дата",
          buttons:[{
            type: "postback",
            payload: "Custom_middle_1_1",
            title: "Тариф"
          },{
            type: "postback",
            payload: "CUSTOM_1_2_1_1",
            title: "Цэнэглэгч карт"
          }]
        }
      }
    }
  };  
  callSendAPI(messageData);
}
function Custom_middle_2(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "button",
          text: "Өнгөлөг Хоног",
          buttons:[{
            type: "postback",
            payload: "Custom_middle_2_1",
            title: "Тариф"
          },{
            type: "postback",
            payload: "CUSTOM_1_2_1_2",
            title: "Цэнэглэгч карт"
          }]
        }
      }
    }
  };  
  callSendAPI(messageData);
}
function Custom_middle_3(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "button",
          text: "Skyphone 3.0",
          buttons:[{
            type: "postback",
            payload: "Custom_middle_3_1",
            title: "Тариф"
          },{
            type: "postback",
            payload: "CUSTOM_1_2_1_3",
            title: "Цэнэглэгч карт"
          }]
        }
      }
    }
  };  
  callSendAPI(messageData);
}
function tulhuurug(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {

      text: 'Та дараах түлхүүр үгнээс ашиглан BOT-оос мэдээллээ лавлана уу.' ,
      metadata: "ZOL_DEFINED_METADATA",
            
      quick_replies: [
        {
          "content_type":"text",
          "title":"Урамшуулал",
          "payload":"tulhuur1"
        },
        
        {
          "content_type":"text",
          "title":"Өнгөлөг",
          "payload":"tulhuur3"
        },
        {
          "content_type":"text",
          "title":"Дата",
          "payload":"tulhuur4"
        },
        {
          "content_type":"text",
          "title":"Тохиргоо",
          "payload":"tulhuur5"
        }
      ]
            
    }
  };

  callSendAPI(messageData);
}


function CUSTOM_1_1_1_1(recipientId) {
    networking.getLatestNews((detail) => {
      newsDetail = detail; 
      var messageData = {
        recipient: {
          id: recipientId
        },
        message: {
          attachment: {
            type: "template",
            payload: {
              template_type: "generic",
              elements: [{
                title: "Хэрэглээ шалгах",
                image_url: `https://www.skytel.mn/app/images/beldsen/home/7.png`,
                subtitle: "Түлхүүр үг = U , Тусгай дугаар = 1510, Багцад дагалдах эрхээс үлдсэн хэрэглээ",
                         
                buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              },{
                title: "Төлбөр шалгах",
                image_url: `https://www.skytel.mn/app/images/beldsen/useful/14.png`,
                       subtitle: "Түлхүүр үг = B , Тусгай дугаар = 1510,  Хэрэглээг мөнгөн дүнгээр   ",
                   
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              },{
              title: "Дата шалгах",
                image_url: `https://www.skytel.mn/app/images/download/SKYtel_logo_transparent.png`,
                    subtitle: "Түлхүүр үг = D , Тусгай дугаар = 1510, Дата хэрэглээ болон дата багцын үлдэгдэл  ",
                           
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              },{
                title: "Хэрэглээ шалгах",
                image_url: `https://www.skytel.mn/app/images/download/SKYtel_logo_transparent.png`,
                subtitle: "Түлхүүр үг = 201708, Тусгай дугаар = 1510, Өмнөх сарын төлбөр  ",
                           
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              }]
            }
          }
        }
      };  

      callSendAPI(messageData);
  });
   }

function CUSTOM_2_2_1(recipientId) {
    networking.getLatestNews((detail) => {
      newsDetail = detail; 
      var messageData = {
        recipient: {
          id: recipientId
        },
        message: {
          attachment: {
            type: "template",
            payload: {
              template_type: "generic",
              elements: [{
                title: "Энгийн дугаар",
                image_url: `https://www.skytel.mn/app/images/beldsen/useful/17.png`,
                subtitle: "Үнэ-3000 Нэгж-1000 Хоног-30 Урамшуулал-6 сарын 247+сар бүр 1GB дата /6сар/",
                         
                buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              },{
                title: "Азын дугаар",
                image_url: `https://www.skytel.mn/app/images/beldsen/useful/17.png`,
                       subtitle: "Үнэ-10000 Нэгж-5000 Хоног-30 Урамшуулал-6 сарын 247+сар бүр 1GB дата /6сар/",
                   
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              }]
            }
          }
        }
      };  

      callSendAPI(messageData);
  });
   }

  function CUSTOM_2_2_2(recipientId) {
    var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "button",
          text: "Хэрэглэгч та цэнэглэгч картаар цэнэглэх бүртээ shake and win урамшуулалд оролцох 1 код авах бөгөөд тус кодоо Skytel application-д нэвтрэн эсвэл Skytel.mn сайтаар хандан shake & win урамшууллын хэсэгт оруулж урамшуулалд оролцоно. Цэнэглэлтэнд дагалдах код 3 өдөрт хүчинтэй байна.",
          buttons:[
                {
                              "type": "web_url",
                              "url": "https://www.skytel.mn/shakewin", 
                              "title": "Энд дарна уу"
                            }
          ]
        }
      }
    }
  };  

  callSendAPI(messageData);
   } 
                 
    function CUSTOM_2_1_2(recipientId) {
 var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "button",
          text: "Гар утасны лизингийн урамшууллын мэдээллийг 1515 лавлах төвд эсвэл онлайн лавлахтай холбогдож мэдээлэл авна уу.",
          buttons:[
                {
                              "type": "web_url",
                              "url": "https://www.skytel.mn/shop/product", 
                              "title": "Энд дарна уу"
                            }
          ]
        }
      }
    }
  };  

  callSendAPI(messageData);
}                     
  function ip(recipientId) {
    networking.getLatestNews((detail) => {
      newsDetail = detail; 
      var messageData = {
        recipient: {
          id: recipientId
        },
        message: {
          attachment: {
            type: "template",
            payload: {
              template_type: "generic",
              elements: [{
                title: "3000₮",
                image_url: `https://www.skytel.mn/uploads/products/201611/200/uploaded_c89f88290eb7900f8223d030c7726ca7fad71a0b.png`,
                subtitle: "3000 НЭГЖ",
                item_url: `https://www.skytel.mn/content/branches/Ulaanbaatar`,                
               buttons: [ {
                  type: "postback",
                  title: "Авах",
                  payload: `CUSTOM_Back`,
                }],
              },{
              title: "5000₮",
                image_url: `https://www.skytel.mn/uploads/products/201611/200/uploaded_20c2948c322bbafc7b450082b9770738c73e982d.png`,
                subtitle: "5,000 НЭГЖ",
                item_url: `https://www.skytel.mn/content/branches/Ulaanbaatar`,                  
               buttons: [ {
                  type: "postback",
                  title: "Авах",
                  payload: `CUSTOM_Back`,
                }],
              },{
              title: "8000₮",
                image_url: `https://www.skytel.mn/uploads/products/201611/200/uploaded_5d2714170876bf6c9294201ca342011273d0b94f.png`,
                subtitle: "8,000 НЭГЖ",
                item_url: `https://www.skytel.mn/content/branches/Ulaanbaatar`,               
               buttons: [ {
                  type: "postback",
                  title: "Авах",
                  payload: `CUSTOM_Back`,
                }],
              },{
                title: "10000₮",
                image_url: `https://www.skytel.mn/uploads/products/201611/200/uploaded_2438e989248a6877927d01a1ca666fac4a61ed23.png`,
                subtitle: "10,000 НЭГЖ",
                item_url: `https://www.skytel.mn/content/branches/Ulaanbaatar`,               
               buttons: [ {
                  type: "postback",
                  title: "Авах",
                  payload: `CUSTOM_Back`,
                }],
              },{
          title: "15000₮",
                image_url: `https://www.skytel.mn/uploads/products/201611/200/uploaded_fd0a5890ced07d42a8e6d556ba7a03085a4d13b8.png`,
                subtitle: "15,000 НЭГЖ",
                item_url: `https://www.skytel.mn/content/branches/Ulaanbaatar`,               
               buttons: [ {
                  type: "postback",
                  title: "Авах",
                  payload: `CUSTOM_Back`,
                }],
              },{
             title: "60,000₮",
                image_url: `https://www.skytel.mn/uploads/products/201611/200/uploaded_07ade0c1fc579108f48608f2e0ef6a1f92e732da.png`,
                subtitle: "60,000 НЭГЖ",
                item_url: `https://www.skytel.mn/content/branches/Ulaanbaatar`,              
               buttons: [ {
                  type: "postback",
                  title: "Авах",
                  payload: `CUSTOM_Back`,
                }],
              },{
                 title: "Налайх салбар Налайх дүүрэг, 2-р хороо, МХС ТӨК байр, 1-р давхар 7611-2003",
                image_url: `https://www.skytel.mn/uploads/news/4a3aa5931d8b21ef59e1e2b27555fe2384445c82.png`,
                subtitle: "Даваа-Баасан: 09:00-19:00 Бямба: 11:00-16:00 Ням:Амарна",
                item_url: `https://www.skytel.mn/content/branches/Ulaanbaatar`,               
               buttons: [ {
                  type: "postback",
                  title: "Буцах",
                  payload: `CUSTOM_Back`,
                }],
              }]
            }
          }
        }
      };  

      callSendAPI(messageData);
  });
  

  }

/*
 * Delivery Confirmation Event
 *
 * This event is sent to confirm the delivery of a message. Read more about 
 * these fields at https://developers.facebook.com/docs/messenger-platform/webhook-reference/message-delivered
 *
 */
function receivedDeliveryConfirmation(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;
  var delivery = event.delivery;
  var messageIDs = delivery.mids;
  var watermark = delivery.watermark;
  var sequenceNumber = delivery.seq;

  if (messageIDs) {
    messageIDs.forEach(function(messageID) {
      console.log("Received delivery confirmation for message ID: %s", 
        messageID);
    });
  }

  console.log("All message before %d were delivered.", watermark);
}


/*
 * Postback Event
 *
 * This event is called when a postback is tapped on a Structured Message. 
 * https://developers.facebook.com/docs/messenger-platform/webhook-reference/postback-received
 * 
 */
function receivedPostback(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;
  var timeOfPostback = event.timestamp;

  // The 'payload' param is a developer-defined field which is set in a postback 
  // button for Structured Messages. 
  var payload = event.postback.payload;
  
    console.log("Received postback for user %d and page %d with payload '%s' " + 
    "at %d", senderID, recipientID, payload, timeOfPostback);
  
    if((/^CUSTOM_NEWS_/).test(payload)){
        var detailID = payload.substring(12, payload.length);
        sendTextMessage(senderID, stringUtils.getSubWords(newsDetail[detailID].intro, charLimitTextMsg));
    }
    
    switch (payload){
      
             case 'CUSTOM_Back':
            CUSTOM_new(senderID); 
            break;
             
    case 'CUSTOM_1':
            CUSTOM_1(senderID); 
            break;        
      case 'CUSTOM_2':
            startUramshuulal(senderID); 
            break;
     case 'CUSTOM_3':
            CUSTOM_3(senderID); 
            break;         
     case 'CUSTOM_2_1':
            CUSTOM_2_1(senderID); 
            break;
     case 'CUSTOM_2_2':
            CUSTOM_2_2(senderID); 
            break; 
     case 'CUSTOM_2_3':
            CUSTOM_2_3(senderID); 
            break;
            
              case 'CUSTOM_3_2_2':
            CUSTOM_3_2_2(senderID); 
            break; 
    
           
             case 'CUSTOM_2_2_1':
            CUSTOM_2_2_1(senderID); 
            break; 
             case 'CUSTOM_2_2_2':
            CUSTOM_2_2_2(senderID); 
            break; 
           
             
              
              case 'CUSTOM_1_1':
            CUSTOM_1_1(senderID); 
            break; 
              case 'CUSTOM_1_2':
            CUSTOM_1_2(senderID); 
            break; 
              case 'CUSTOM_1_3':
            CUSTOM_1_3(senderID); 
            break; 
              case 'CUSTOM_1_1_1':
            CUSTOM_1_1_1(senderID); 
            break; 
              case 'CUSTOM_1_1_2':
            CUSTOM_1_1_2(senderID); 
            break; 
              case 'CUSTOM_1_1_3':
            CUSTOM_1_1_3(senderID); 
            break; 
              case 'CUSTOM_1_2_1':
            CUSTOM_1_2_1(senderID); 
            break; 
              case 'CUSTOM_1_2_2':
            CUSTOM_1_2_2(senderID); 
            break; 
              case 'CUSTOM_1_2_3':
            CUSTOM_1_2_3(senderID); 
            break; 
              case 'CUSTOM_1_3_1':
            CUSTOM_1_3_1(senderID); 
            break; 
              case 'CUSTOM_1_3_2':
            CUSTOM_1_3_2(senderID); 
            break;
              case 'CUSTOM_1_1_1_1':
            CUSTOM_1_1_1_1(senderID); 
            break; 
              case 'CUSTOM_1_1_1_2':
            CUSTOM_1_1_1_2(senderID); 
            break; 
             case 'CUSTOM_1_2_2_3':
            CUSTOM_1_2_2_3(senderID); 
            break; 
             
              case 'CUSTOM_1_1_2_1':
            CUSTOM_1_1_2_1(senderID); 
            break; 
              case 'CUSTOM_1_1_2_2':
            CUSTOM_1_1_2_2(senderID); 
            break; 
            
              case 'CUSTOM_1_2_1_1':
            CUSTOM_1_2_1_1(senderID); 
            break; 
              case 'CUSTOM_1_2_1_2':
            CUSTOM_1_2_1_2(senderID); 
            break; 
              case 'CUSTOM_1_2_1_3':
            CUSTOM_1_2_1_3(senderID); 
            break; 
               case 'Custom_middle_1':
            Custom_middle_1(senderID); 
            break; 
            
              case 'Custom_middle_2':
            Custom_middle_2(senderID); 
            break; 
               case 'Custom_middle_3':
            Custom_middle_3(senderID); 
            break; 
            
              case 'CUSTOM_3_2':
            CUSTOM_3_2(senderID); 
            break;
              case 'CUSTOM_3_3':
            CUSTOM_3_3(senderID); 
            break;
              case 'CUSTOM_3_3_1':
            CUSTOM_3_3_1(senderID); 
            break;
              case 'CUSTOM_3_3_2':
            CUSTOM_3_3_2(senderID); 
            break;
             case 'CUSTOM_3_1':
            CUSTOM_3_1(senderID); 
            break;   
             
                case 'CUSTOM_3_1':
            CUSTOM_3_1(senderID); 
            break; 
        case 'CUSTOM_3_1_1':
            CUSTOM_3_1_1(senderID); 
            break; 
          case 'CUSTOM_salbarub':
              CUSTOM_salbarub(senderID); 
            break;
            
            case 'CUSTOM_2_3_2':
              CUSTOM_2_3_2(senderID); 
            break;
             case 'CUSTOM_3_2_1':
              CUSTOM_3_2_1(senderID); 
            break;
              case 'CUSTOM_2_1_2':
              CUSTOM_2_1_2(senderID); 
            break;
        
             case 'CUSTOM_salbaroron':
              CUSTOM_salbaroron(senderID); 
            break;
             case 'CUSTOM_salbaroron_tuv':
              CUSTOM_salbaroron_tuv(senderID); 
            break;
             case 'CUSTOM_salbaroron_baruun':
              CUSTOM_salbaroron_baruun(senderID); 
            break;
             case 'CUSTOM_salbaroron_zuun':
              CUSTOM_salbaroron_zuun(senderID); 
            break;
        case 'CUSTOM_GET_STARTED_PAYLOAD':
            sendStartButtons(senderID); 
            break; 
 
        case 'CUSTOM_START_NEW_SERVICE':
            sendTypingOn(senderID);
            send123Buttons(senderID);
            break; 
        case 'CUSTOM_START_NEWS':
            sendTypingOn(senderID);
            sendNewsMessage(senderID);
            break;
         case 'CUSTOM_3_3_1_1':
            sendTextMessage2(senderID, "Та дараах тохиргоог гар утсандаа хийнэ үү. Settings-More setting-Mobile network-Access point names Name-Skytel Apn / style, net, skytel / аль нэгийг бичээд хадгална. Утсаа унтрааж асаана.");
            break;
               case 'CUSTOM_2_1_1':
            sendTextMessage2(senderID, "11/30н хүртэл  Дараа төлбөрт үйлчилгээний энгийн дугаар: 0₮/ Азын дугаар: 60000₮  Багцаасаа хамаараад 20000₮ болон 50000₮ барьцаа байршуулна Эхний 3 сар  суурь хураамжнаас 30% хөнгөлнө.");
            break;
      case 'CUSTOM_2_2_3':
            sendTextMessage2(senderID, "Та Shake and share үйлчилгээний энгийн дугаарыг-1,000₮-р үйлчилгээний 30хоног-1,000нэгж, 180 хоног 247 эрх+ 6 сарын турш сар бүр 1GB дата эрхтэй авах боломжтой. Мөн та 1990 онд төрсөн бол үйлчилгээний салбарт хандан Shake and Share үйлчилгээний шинэ дугаараа үнэгүй аваарай.");
            break;
              case 'CUSTOM_2_3_1':
            sendTextMessage2(senderID, "Скаймедиа үйлчилгээний хэрэглэгч өөрийн гэрээндээ Скайтелийн дараа  болон урьдчилсан төлбөрт үйлчилгээний дугаарыг бүртгүүлснээр Smart home үйлчилгээний урамшууллыг авна. Та өөрийн дугаараас гадна 1-5 хүртэлх дугааруудыг тухайн үйлчилгээнд бүртгүүлснээр хоорондоо ХЯЗГААРГҮЙ  ЯРИХ, сар бүр ДАТА эрх авахаас гадна КИНО ГАЛЕРЕЙ үйлчилгээг үнэ төлбөргүй 2018/06/01-н хүртэл ашиглах боломжтой. 2017/12/31-с өмнө амжиж урамшууллаа аваарай.");
            break;
             
         
         case 'CUSTOM_3_3_1_2':
            sendTextMessage2(senderID, "Та дараах тохиргоог гар утсандаа хийнэ үү. Settings - General - Network - Cellural Data Network - APN - хэсгийг сонгож style гэж бичнэ.");
            break;
              case 'CUSTOM_3_3_2_1':
            sendTextMessage2(senderID, "Та дараах тохиргоог гар утсандаа хийнэ үү. Menu->Settings->More->Mobile networks->Search network automatically->Skytel сонгоно.");
            break;
              case 'CUSTOM_1_2_2_2':
            sendTextMessage2(senderID, "Та  14-22насны хэрэглэгч бөгөөд SHAKE & SHARE  үйлчилгээнд шилжих бол өөрт ойрхон үйлчилгээний салбарт өөрийн цахим үнэмлэх эсвэл төрсний гэрчилгээтэйгээ хандан SHAKE & SHARE үйлчилгээнд бүртгүүлэх боломжтой. Бүртгүүлэхэд төлбөргүй.");
            break;
              case 'CUSTOM_1_1_2_3':
            sendTextMessage2(senderID, "МОНГОЛдоо үүрэн болон суурин холбооны бүх сүлжээнд хүссэнээрээ хязгааргүй ярина. Мөн МОНГОЛдоо хамгийн их дата эрхтэй бөгөөд тухайн эрхээ 3 хүртэлх дотны хүндээ хуваалцах буюу илгээх эрхтэй. Төлбөр төлөх уян хатан боломжууд, ОУ-н яриа, мессэж, дата роумингийн үйлчилгээг сонгох эрхтэйгээс гадна 21MBPS хүртэлх хурдтайгаар интернэт ашиглах зэрэг олон давуу талуудыг МОНГОЛдоогоос авах боломжтой.");
            break;
            
              case 'Custom_middle_1_1':
            sendTextMessage2(senderID, "Яриа-60₮, Мессэж-20₮, Дата-1MB 6₮");
            break;
            case 'Custom_middle_2_1':
            sendTextMessage2(senderID, "Яриа-60₮, Мессэж-20₮ , Дата-1MB 12₮");
            break;
            case 'Custom_middle_3_1':
            sendTextMessage2(senderID, "Яриа-30₮, Мессэж-(Бусад сүлжээ 20₮,Сүлжээндээ 0₮),Дата-1MB 12₮");
            break;
         
             case 'CUSTOM_1_2_2_1':
              CUSTOM_1_2_2_1(senderID); 
            break;
           
              case 'CUSTOM_1_1_1_3':
            sendTextMessage2(senderID, "Та www.skytel.mn сайтад хандан орон зай, цаг хугацааны хязгаарлалтгүйгээр хэрэглээний төлбөрөө төлөх боломжтой. Төлбөр амжилттай төлөгдмөгц үйлчилгээний эрх шууд нээгдэх нь банкаар дамжуулан төлөхөөс илүү давуу талтай.Та бүх арилжааны банкуудын төлбөрийн картыг ашиглах боломжтой.Мөн Skytel.mn сайтаар хугацаандаа буюу сар  бүрийн 20-с өмнө төлбөрөө төлсөн тохиолдолд 5%-н хөнгөлөлт эдлэх давуу талтай.");
            break;
             case 'CUSTOM_viewmore_1':
            sendTextMessage2(senderID, "Шинээр account үүсгэх Текст статус бичих Check in хийх Зураг харах Facebook-н видео үзэх Like, comment,share хийх Онлайн хүмүүс харах Friend request, notification харах.");
            break;
         case 'CUSTOM_viewmore_2':
            sendTextMessage2(senderID, "Чатлах Стикер илгээх  Зураг илгээх Зураг хүлээн авах Видео илгээх* Өөрт ирсэн видеог үзэх Voice record илгээх Өөрт ирсэн record сонсох Байршил илгээх.");
            break;
             case 'CUSTOM_viewmore_3':
            sendTextMessage2(senderID, "Voice дуудлага хийх* Voice дуудлага хүлээн авах* Video дуудлага хийх* Video дуудлага хүлээн авах* Giphy хөдөлгөөнт зулаг илгээх");
            break;
     
         
             case 'CUSTOM_3_2_3':
            sendTextMessage2(senderID, "ERROR:691 Холболт хийгдэхэд алдаа гарлаа. Та нууц үгээ дахин оруулна уу? , Таны хэрэглэгчийн нэр, нууц үг буруу байна. Эсвэл үйлчилгээний хугацаа, мэдээлэл татаж авах эрх дууссан үед ийм алдаа гарна.ERROR:680 CCU-550 modem evdo for vista support татаж программыг ажиллуулахад  гэсэн алдаа гарвал татаж авсан програмыг ашиглахгүйгээр Vista үйлдлийн системийн dial up модемоор холболт хийгдэнэ. Windows 95, 98, Me NT, 2K & XP үйлдлийн систем дээр ажиллана.ERROR:718 Компьютерийг restart хийх (унтрааж асаах ) хэрэгтэй. Модем драйверыг дахин суулгана");
            break;
             case 'CUSTOM_3_3_2_2':
            sendTextMessage2(senderID, "Та дараах тохиргоог гар утсандаа хийнэ үү. Settings-Carrier-Automatic-g idevhijuulne. Bas Settings->Cellular->Voice & Data->3G-g  сонгоно.");
            break;
        case 'CUSTOM_FROM_123_NEWS':
                    sendNewsMessage(senderID); 
        //sendTextMessage(senderID, "Та 123-г ашиглан 247 багц авахын тулд 247 гэсэн түлхүүр үгийг //123 тусгай дугаарт илгээхэд хангалттай. Дагалдах эрх үйлчилгээний 30 хоног. Үнэ 5000₮");
        break; 
        case 'CUSTOM_123_DATA_PACKAGE':
            sendDataQuickReply(senderID); 
            break; 
        case 'CUSTOM_123_FB_PACKAGE':
            sendTextMessage(senderID, "Та 123-г ашиглан Facebook багц авахын тулд facebook гэсэн түлхүүр үгийг 123 тусгай дугаарт илгээхэд хангалттай. Дагалдах эрх үйлчилгээний 30 хоног. Үнэ 5000₮");
            break; 
        case 'CUSTOM_123_247_PACKAGE':
            sendTextMessage(senderID, "Та 123-г ашиглан 247 багц авахын тулд 247 гэсэн түлхүүр үгийг 123 тусгай дугаарт илгээхэд хангалттай. Дагалдах эрх үйлчилгээний 30 хоног. Үнэ 5000₮");
            break; 
        default: 
            // When a postback is called, we'll send a message back to the sender to 
            // let them know it was successful
//            sendTextMessage(senderID, "Postback called");
            break; 
    }
}

/*
 * Message Read Event
 *
 * This event is called when a previously-sent message has been read.
 * https://developers.facebook.com/docs/messenger-platform/webhook-reference/message-read
 * 
 */
function receivedMessageRead(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;

  // All messages before watermark (a timestamp) or sequence have been seen.
  var watermark = event.read.watermark;
  var sequenceNumber = event.read.seq;

  console.log("Received message read event for watermark %d and sequence " +
    "number %d", watermark, sequenceNumber);
}

/*
 * Account Link Event
 *
 * This event is called when the Link Account or UnLink Account action has been
 * tapped.
 * https://developers.facebook.com/docs/messenger-platform/webhook-reference/account-linking
 * 
 */
function receivedAccountLink(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;

  var status = event.account_linking.status;
  var authCode = event.account_linking.authorization_code;

  console.log("Received account link event with for user %d with status %s " +
    "and auth code %s ", senderID, status, authCode);
}

/*
 * Send an image using the Send API.
 *
 */
function sendImageMessage(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "image",
        payload: {
          url: SERVER_URL + "/assets/rift.png"
        }
      }
    }
  };

  callSendAPI(messageData);
}

/*
 * Send a Gif using the Send API.
 *
 */
function sendGifMessage(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "image",
        payload: {
          url: SERVER_URL + "/assets/instagram_logo.gif"
        }
      }
    }
  };

  callSendAPI(messageData);
}

/*
 * Send audio using the Send API.
 *
 */
function sendAudioMessage(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "audio",
        payload: {
          url: SERVER_URL + "/assets/sample.mp3"
        }
      }
    }
  };

  callSendAPI(messageData);
}

/*
 * Send a video using the Send API.
 *
 */
function sendVideoMessage(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "video",
        payload: {
          url: SERVER_URL + "/assets/allofus480.mov"
        }
      }
    }
  };

  callSendAPI(messageData);
}

/*
 * Send a video using the Send API.
 *
 */
function sendFileMessage(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "file",
        payload: {
          url: SERVER_URL + "/assets/test.txt"
        }
      }
    }
  };

  callSendAPI(messageData);
}

/*
 * Send a text message using the Send API.
 *
 */
function sendTextMessage(recipientId, messageText) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      text: messageText,
      metadata: "DEVELOPER_DEFINED_METADATA"
    }
  };

  callSendAPI(messageData);
}

function sendTextMessage2(recipientId, messageText) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      text: messageText,
      metadata: "DEVELOPER_DEFINED_METADATA",
        quick_replies: [
        {
          "content_type":"text",
          "title":"Буцах",
          "payload":"maunfunc"
        },
       
      ]
    }
  };

  callSendAPI(messageData);
}
function operator(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "button",
          text: "Та доорх холбоос дээр дарна уу",
          buttons:[{
            type: "web_url",
            url: "https://www.skytel.mn/",
            title: "Дарах"
          }]
        }
      }
    }
  };  

  callSendAPI(messageData);
}

/*
 * Send a button message using the Send API.
 *
 */
function sendButtonMessage(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "button",
          text: "This is test text",
          buttons:[{
            type: "web_url",
            url: "https://www.oculus.com/en-us/rift/",
            title: "Open Web URL"
          }, {
            type: "postback",
            title: "Trigger Postback",
            payload: "DEVELOPED_DEFINED_PAYLOAD"
          }, {
            type: "phone_number",
            title: "Call Phone Number",
            payload: "+16505551234"
          }]
        }
      }
    }
  };  

  callSendAPI(messageData);
}
//TODO mine 
function send123Buttons(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "button",
          text: "Танд манай 123 шинэ үйлчилгээг танилцуулж байна",
          buttons:[{
            type: "postback",
            payload: "CUSTOM_123_DATA_PACKAGE",
            title: "Дата багц авах"
          }, {
            type: "postback",
            title: "Facebook багц авах",
            payload: "CUSTOM_123_FB_PACKAGE"
          }, {
            type: "postback",
            title: "Сүүлийн үеийн мэдээ",
            payload: "CUSTOM_FROM_123_NEWS"
          }]
        }
      }
    }
  };  

  callSendAPI(messageData);
}

var newsDetail; 

//TODO mine 
function sendNewsMessage(recipientId) {
    
  networking.getLatestNews((detail) => {
      newsDetail = detail; 
      var messageData = {
        recipient: {
          id: recipientId
        },
        message: {
          attachment: {
            type: "template",
            payload: {
              template_type: "generic",
              elements: [{
                title: detail[0].title,
                subtitle: stringUtils.getSubWords(detail[0].intro, charLimitTitle),
                item_url: `https://www.skytel.mn/content/${detail[0].id}/view`,               
                image_url: detail[0].image,
                buttons: [{
                  type: "web_url",
                  url: `https://www.skytel.mn/content/${detail[0].id}/view`,
                  title: "Мэдээг унших"
                }, {
                  type: "postback",
                  title: "Тойм унших",
                  payload: `CUSTOM_NEWS_0`,
                }],
              },{
                title: detail[1].title,
                subtitle: stringUtils.getSubWords(detail[1].intro, charLimitTitle),
                item_url: `https://www.skytel.mn/content/${detail[1].id}/view`,               
                image_url: detail[1].image,
                buttons: [{
                  type: "web_url",
                  url: `https://www.skytel.mn/content/${detail[1].id}/view`,
                  title: "Мэдээг унших"
                }, {
                  type: "postback",
                  title: "Тойм унших",
                  payload: `CUSTOM_NEWS_1`,
                }],
              },{
                title: detail[2].title,
                subtitle: stringUtils.getSubWords(detail[2].intro, charLimitTitle),
                item_url: `https://www.skytel.mn/content/${detail[2].id}/view`,               
                image_url: detail[2].image,
                buttons: [{
                  type: "web_url",
                  url: `https://www.skytel.mn/content/${detail[2].id}/view`,
                  title: "Мэдээг унших"
                }, {
                  type: "postback",
                  title: "Тойм унших",
                  payload: `CUSTOM_NEWS_2`,
                }],
              },{
                title: detail[3].title,
                subtitle: stringUtils.getSubWords(detail[3].intro, charLimitTitle),
                item_url: `https://www.skytel.mn/content/${detail[3].id}/view`,               
                image_url: detail[3].image,
                buttons: [{
                  type: "web_url",
                  url: `https://www.skytel.mn/content/${detail[3].id}/view`,
                  title: "Мэдээг унших"
                }, {
                  type: "postback",
                  title: "Тойм унших",
                  payload: `CUSTOM_NEWS_3`,
                }],
              }]
            }
          }
        }
      };  

      callSendAPI(messageData);
  });
  
}

/*
 * Send a receipt message using the Send API.
 *
 */
function sendReceiptMessage(recipientId) {
  // Generate a random receipt ID as the API requires a unique ID
  var receiptId = "order" + Math.floor(Math.random()*1000);

  var messageData = {
    recipient: {
      id: recipientId
    },
    message:{
      attachment: {
        type: "template",
        payload: {
          template_type: "receipt",
          recipient_name: "Peter Chang",
          order_number: receiptId,
          currency: "USD",
          payment_method: "Visa 1234",        
          timestamp: "1428444852", 
          elements: [{
            title: "Oculus Rift",
            subtitle: "Includes: headset, sensor, remote",
            quantity: 1,
            price: 599.00,
            currency: "USD",
            image_url: SERVER_URL + "/assets/riftsq.png"
          }, {
            title: "Samsung Gear VR",
            subtitle: "Frost White",
            quantity: 1,
            price: 99.99,
            currency: "USD",
            image_url: SERVER_URL + "/assets/gearvrsq.png"
          }],
          address: {
            street_1: "1 Hacker Way",
            street_2: "",
            city: "Menlo Park",
            postal_code: "94025",
            state: "CA",
            country: "US"
          },
          summary: {
            subtotal: 698.99,
            shipping_cost: 20.00,
            total_tax: 57.67,
            total_cost: 626.66
          },
          adjustments: [{
            name: "New Customer Discount",
            amount: -50
          }, {
            name: "$100 Off Coupon",
            amount: -100
          }]
        }
      }
    }
  };

  callSendAPI(messageData);
}

/*
 * Send a message with Quick Reply buttons.
 *
 */
function sendQuickReply(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      text: "What's your favorite movie genre?",
      metadata: "DEVELOPER_DEFINED_METADATA",
      quick_replies: [
        {
          "content_type":"text",
          "title":"Action",
          "payload":"DEVELOPER_DEFINED_PAYLOAD_FOR_PICKING_ACTION"
        },
        {
          "content_type":"text",
          "title":"Comedy",
          "payload":"DEVELOPER_DEFINED_PAYLOAD_FOR_PICKING_COMEDY"
        },
        {
          "content_type":"text",
          "title":"Drama",
          "payload":"DEVELOPER_DEFINED_PAYLOAD_FOR_PICKING_DRAMA"
        }
      ]
    }
  };

  callSendAPI(messageData);
}
//TODO mine 
function sendDataQuickReply(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      text: "Та дата багцыг 123-с дараах 3-н төрлөөс сонгон авах боломжтой",
      metadata: "ZOL_DEFINED_METADATA",
      quick_replies: [
        {
          "content_type":"text",
          "title":"1GB",
          "payload":"CUSTOM_QUICK_DATA_1GB"
        },
        {
          "content_type":"text",
          "title":"2GB",
          "payload":"CUSTOM_QUICK_DATA_2GB"
        },
        {
          "content_type":"text",
          "title":"10GB",
          "payload":"CUSTOM_QUICK_DATA_10GB"
        }
      ]
    }
  };

  callSendAPI(messageData);
}

//MINE
function sendStartButtons(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "button",
          text: "Skytel Messenger-т тавтай морил",
          buttons:[{
            type: "postback",
            payload: "CUSTOM_START_NEW_SERVICE",
            title: "Шинэ үйлчилгээ"
          }, {
            type: "postback",
            title: "Шинэ мэдээ",
            payload: "CUSTOM_START_NEWS"
          }]
        }
      }
    }
  };  
	sendTypingOff(recipientId); 
  callSendAPI(messageData);
}

/*
 * Send a read receipt to indicate the message has been read
 *
 */
function sendReadReceipt(recipientId) {
  console.log("Sending a read receipt to mark message as seen");

  var messageData = {
    recipient: {
      id: recipientId
    },
    sender_action: "mark_seen"
  };

  callSendAPI(messageData);
}

/*
 * Turn typing indicator on
 *
 */
function sendTypingOn(recipientId) {
  console.log("Turning typing indicator on");

  var messageData = {
    recipient: {
      id: recipientId
    },
    sender_action: "typing_on"
  };

  callSendAPI(messageData);
}

/*
 * Turn typing indicator off
 *
 */
function sendTypingOff(recipientId) {
  console.log("Turning typing indicator off");

  var messageData = {
    recipient: {
      id: recipientId
    },
    sender_action: "typing_off"
  };

  callSendAPI(messageData);
}

/*
 * Send a message with the account linking call-to-action
 *
 */
function sendAccountLinking(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "button",
          text: "Welcome. Link your account.",
          buttons:[{
            type: "account_link",
            url: SERVER_URL + "/authorize"
          }]
        }
      }
    }
  };  

  callSendAPI(messageData);
}

/*
 * Call the Send API. The message data goes in the body. If successful, we'll 
 * get the message id in a response 
 *
 */
function callSendAPI(messageData) {
  request({
    uri: 'https://graph.facebook.com/v2.6/me/messages',
    qs: { access_token: PAGE_ACCESS_TOKEN },
    method: 'POST',
    json: messageData

  }, function (error, response, body) {
    if (!error && response.statusCode == 200) {
      var recipientId = body.recipient_id;
      var messageId = body.message_id;

      if (messageId) {
        console.log("Successfully sent message with id %s to recipient %s", 
          messageId, recipientId);
      } else {
      console.log("Successfully called Send API for recipient %s", 
        recipientId);
      }
    } else {
      console.error(response.error);
    }
  });  
}

// Start server
// Webhooks must be available via SSL with a certificate signed by a valid 
// certificate authority.

//var privateKey = fs.readFileSync('/home/www/ssl_old/20150330 SSL/server.key');
//var certificate = fs.readFileSync('/home/www/ssl_old/20150330 SSL/ssl_certificate.crt' );
//https.createServer({
//    key: privateKey,
//    cert: certificate
//}, app).listen(app.get('port'));

app.listen(app.get('port'), function() {
  console.log('Node app is running on port', app.get('port'));
});

module.exports = app;


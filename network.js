
const jsonfile = require('jsonfile')
const request = require("request")

const newsListFile = 'data/news.json'
const newsListURL = "https://www.skytel.mn/api/content/list?category=7&page=1"; 

const newsDetailFile = 'data/news_detail.json'
        
var currentNews = []; 

function getLatestNews(){ 
    var currentLatestId = getLastNewsId();
    console.log("$$$$ currentLatestId: "+currentLatestId);
    request({
        url: newsListURL, 
        json: true
    }, (error, response, body) => {
        if (!error && response.statusCode === 200) {
            var newsList = body.result.newsList;
            
            if(newsList[0].id >= currentLatestId){
                console.log("$$$$ new news fount: "+newsList[0].id);
                jsonfile.writeFileSync(newsListFile, newsList, function (err) {
                    console.error(err);
                });
                
                for(var i in newsList){
                    console.log("$$$$ saving news detail: "+newsList[i].id);
                    saveNewsDetail(newsList[i].id); 
                    if(i == 4){
                        break; 
                    }
                }
            }
        }else{
            console.log("$$$$ getting news list: "+response.statusCode );
        }
        
        var detail = jsonfile.readFileSync(newsDetailFile);
        return detail; 
    })
}

module.exports.getLatestNews = getLatestNews;

/**
 * Save the news detail into file 
 * FIXME - Overwriting into the file 4 times! (Bazarvaani!)
 */
function saveNewsDetail(newsId){
    
    var newsDetailURL = `https://www.skytel.mn/api/content/${newsId}/show`; 

    request({
        url: newsDetailURL,
        json: true
    }, (error, response, body) => {
        if (!error && response.statusCode === 200) {
            var newsContent = body.result.content;
            currentNews.push(newsContent); 
            jsonfile.writeFileSync(newsDetailFile, currentNews, function (err) {
                console.error(err);
            });
            console.log("$$$$ saved news detail: "+newsList[i].id);
        }else{
            console.log("$$$$ getting news detail: "+response.statusCode );
        }
    })
}

//Get the id of last news saved in file
function getLastNewsId(){
    var result = jsonfile.readFileSync(newsListFile);
    return result[0].id;
}

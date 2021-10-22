package analysis.urlAnalysis.specific;

import models.track.TrackModel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashSet;
import java.util.Set;


public class ApacheClientManager {
    private static final String HTTP_GET_SET_HEADER_SIG = "<org.apache.http.client.methods.HttpGet: setHeader(java.lang.String,java.lang.String)>";
    private static final String HTTP_POST_SET_HEADER_SIG = "<org.apache.http.client.methods.HttpPost: setHeader(java.lang.String,java.lang.String)>";
    private Logger mLog = LoggerFactory.getLogger("/ApacheClientManager");

    public ApacheClientManager(){
    }
    /**
     *  HttpGet httpGet = new HttpGet(url);
     *  // 设置请求头信息，鉴权
        httpGet.setHeader("Authorization", "Bearer da3efcbf-0845-4fe3-8aba-ee040be542c0");
     * @return
     */
    public Set<TrackModel> getApacheClientUrls(TrackModel input){
        Set<TrackModel> res = new HashSet<>();
        System.out.println("Start Apache Client URL Analysis...");

        return res;


    }
}

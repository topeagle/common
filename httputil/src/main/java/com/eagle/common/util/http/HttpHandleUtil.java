package com.eagle.common.util.http;

import java.io.IOException;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.apache.http.Consts;
import org.apache.http.HttpEntity;
import org.apache.http.HttpStatus;
import org.apache.http.NameValuePair;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.CookieStore;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.client.utils.URLEncodedUtils;
import org.apache.http.config.ConnectionConfig;
import org.apache.http.config.MessageConstraints;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.config.SocketConfig;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.socket.PlainConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLContexts;
import org.apache.http.conn.ssl.X509HostnameVerifier;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.BasicCookieStore;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class HttpHandleUtil {

    private static final Logger LOGGER = LoggerFactory.getLogger(HttpHandleUtil.class);

    /**
     * cookie的key
     **/
    private static final String RES_COOKIE_KEY = "res_cookie_key";

    /**
     * 返回值的key
     **/
    private static final String RES_RESULT_KEY = "res_result_key";

    /**
     * 返回类型，可以放在传递的参数里面
     ***/
    public static final String CONTENT_TYPE_KEY = "contenttype";

    /**
     * json串的键，可以放在传递的参数里面
     ***/
    public static final String JSON_STR_KEY = "jsonkey";

    /**
     * 连接池参数
     **/
    private static final int maxConnection = 1200;// ((TimeoutConfig)
    // HelpPropertiesBinder.getInstance(
    // TimeoutConfig.class).getConfigPropertiesByBinderTypeClass()).maxConnectionProperty();

    /**
     * 每个路由连接数
     ***/
    private static final int maxPerRouteConnection = 1000;// ((TimeoutConfig) HelpPropertiesBinder
    // .getInstance(TimeoutConfig.class).getConfigPropertiesByBinderTypeClass())
    // .maxPerRouteProperty();// 500;

    /**
     * read timeout
     **/
    private static final int readTimeout = 60000;// ((TimeoutConfig)
    // HelpPropertiesBinder.getInstance(
    // TimeoutConfig.class).getConfigPropertiesByBinderTypeClass()).socketTimeoutProperty();//
    // 60000;

    /**
     * connection timeout
     **/
    private static final int connectionTimeOut = 50000;// ((TimeoutConfig)
    // HelpPropertiesBinder.getInstance(
    // TimeoutConfig.class).getConfigPropertiesByBinderTypeClass()).connectionTimeoutProperty();//
    // 10000;

    /**
     * connection request timeout
     **/
    private static final int connectionRequestTimeOut = 50000;// ((TimeoutConfig)
    // HelpPropertiesBinder
    // .getInstance(TimeoutConfig.class).getConfigPropertiesByBinderTypeClass())
    // .requestTimeoutProperty();// 50000;


    // 请求客户端，可以设为全局引用的
    private static CloseableHttpClient httpClient = null;

    // 初始化CLIENT
    static {
        try{
            SSLContext sslContext = SSLContexts.custom().useTLS().build();
            // https
            // 创建TrustManager()
            // 用于解决javax.net.ssl.SSLPeerUnverifiedException: peer not
            // authenticated
            X509TrustManager trustManager = new X509TrustManager() {
                @Override
                public void checkClientTrusted(java.security.cert.X509Certificate[] chain,
                                               String authType) throws java.security.cert.CertificateException {
                    // TODO Auto-generated method stub

                }

                @Override
                public void checkServerTrusted(java.security.cert.X509Certificate[] chain,
                                               String authType) throws java.security.cert.CertificateException {
                    // TODO Auto-generated method stub

                }

                @Override
                public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                    // TODO Auto-generated method stub
                    return null;
                }
            };

            // 创建HostnameVerifier
            // 用于解决javax.net.ssl.SSLException: hostname in certificate didn't
            // match: <123.125.97.66> != <123.125.97.241>
            X509HostnameVerifier hostnameVerifier = new X509HostnameVerifier() {
                @Override
                public void verify(String host, SSLSocket ssl) throws IOException {
                }

                @Override
                public void verify(String host, String[] cns, String[] subjectAlts)
                        throws SSLException {
                }

                @Override
                public boolean verify(String arg0, SSLSession arg1) {
                    return true;
                }

                @Override
                public void verify(String host, java.security.cert.X509Certificate cert)
                        throws SSLException {
                    // TODO Auto-generated method stub

                }
            };

            // TLS1.0与SSL3.0基本上没有太大的差别,可粗略理解为TLS是SSL的继承者，但它们使用的是相同的SSLContext
            // 使用TrustManager来初始化该上下文,TrustManager只是被SSL的Socket所使用
            sslContext.init(null, new TrustManager[]{trustManager}, null);

            Registry<ConnectionSocketFactory> socketFactoryRegistry =
                    RegistryBuilder
                            .<ConnectionSocketFactory>create()
                            .register("http", PlainConnectionSocketFactory.INSTANCE)
                            .register("https",
                                    new SSLConnectionSocketFactory(sslContext, hostnameVerifier))
                            .build();
            PoolingHttpClientConnectionManager connManager =
                    new PoolingHttpClientConnectionManager(socketFactoryRegistry);
            // 设置超时间
            RequestConfig requestConfig = RequestConfig.custom()
                    // 读取数据的超时时间
                    .setSocketTimeout(readTimeout)
                    // 等待建立连接的时间，超过这个时间就会失效
                    .setConnectTimeout(connectionTimeOut)
                    // 一个connection可以有多个request
                    .setConnectionRequestTimeout(connectionRequestTimeOut).build();
            httpClient =
                    HttpClients.custom().setDefaultRequestConfig(requestConfig)
                            .setConnectionManager(connManager).build();
            // Create socket configuration
            SocketConfig socketConfig =
                    SocketConfig.custom().setTcpNoDelay(true).setSoKeepAlive(true)
                            .setSoTimeout(readTimeout).build();
            connManager.setDefaultSocketConfig(socketConfig);
            // 关闭失效的连接
            connManager.closeExpiredConnections();
            // Create message constraints
            MessageConstraints messageConstraints =
                    MessageConstraints.custom().setMaxHeaderCount(200).setMaxLineLength(2000)
                            .build();
            // Create connection configuration
            ConnectionConfig connectionConfig =
                    ConnectionConfig.custom().setMalformedInputAction(CodingErrorAction.IGNORE)
                            .setUnmappableInputAction(CodingErrorAction.IGNORE)
                            .setCharset(Consts.UTF_8).setMessageConstraints(messageConstraints)
                            .build();
            connManager.setDefaultConnectionConfig(connectionConfig);
            connManager.setMaxTotal(maxConnection);
            connManager.setDefaultMaxPerRoute(maxPerRouteConnection);
        }catch (KeyManagementException e) {
            LOGGER.error("KeyManagementException", e);
        } catch (NoSuchAlgorithmException e) {
            LOGGER.error("NoSuchAlgorithmException", e);
        }
    }

    /**
     * @param  url GET请求地址
     * @param  encoding 请求的编码
     * @return 如果请求异常，直接返回NULL
     ***/
    public static String getUrl(String url, String encoding) {
        return (String) getUrlContent(url, encoding, false).get(RES_RESULT_KEY);
    }

    /**
     * @param   url GET请求地址
     * @param   encoding 请求的编码
     * @param  needUrlRecognition  是否需要URL识别并encoding，否(false)就是标准的GET处理；是(true)需要用户自己控制
     * @return 如果请求异常，直接返回NULL
     ***/
    public static String getUrl(String url, String encoding, boolean needUrlRecognition) {
        return (String) getUrlContent(url, encoding, needUrlRecognition).get(RES_RESULT_KEY);
    }

    /**
     * @param  url GET请求地址
     * @param  encoding 请求的编码
     * @return 如果请求异常，直接返回Map
     * @exception NoSuchAlgorithmException
     * @exception KeyManagementException
     ***/
    private static Map getUrlContent(String url, String encoding, boolean needUrlRecognition) {
        // 实例一个返回结果MAP
        Map<String, Object> map = new HashMap<String, Object>();
        // Create a local instance of cookie store
        CookieStore cookieStore = new BasicCookieStore();
        try {
            int questionMarkPost = url.indexOf("?");
            String prefixUrl = url;
            String paramUrl = "";
            if (questionMarkPost > -1) {
                prefixUrl = url.substring(0, questionMarkPost + 1);
                paramUrl = url.substring(questionMarkPost + 1, url.length());
            }

            if (paramUrl != null && (!needUrlRecognition)) {
                paramUrl =
                        URLEncodedUtils.format(
                                URLEncodedUtils.parse(paramUrl, StandardCharsets.UTF_8), "UTF-8");
            }
            HttpGet httpget = new HttpGet(prefixUrl + paramUrl);
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("Executing Get request url{},url lenth {}", httpget.getRequestLine(),
                        httpget.getRequestLine().getUri().length());
            }
            return processContent(httpget, cookieStore, encoding);
        } catch (IOException e) {
            e.printStackTrace();
            if (LOGGER.isErrorEnabled()) {
                LOGGER.error("GET请求失败", e);
            }
        }
        return map;
    }

    /**
     * @param  url POST请求地址
     * @param  params 请求参数
     *               如果直接通过JSON来POST参数，请直接把CONTENT_TYPE_Key,JSON_STR_Key作为KEY.
     *               <p>
     *               <pre>
     *                                         params.put(NetUtils.CONTENT_TYPE_KEY, ContentType.APPLICATION_JSON.getMimeType());
     *                                         params.put(NetUtils.JSON_STR_KEY, "{name:"test",id:100}");
     *                             </pre>
     * @return 如果请求异常，直接返回NULL
     **/
    public static String postUrl(String url, Map<String, String> params) {
        return (String) postUrlContent(url, params, null).get(RES_RESULT_KEY);
    }

    /**
     * @param       url POST请求地址
     * @param        params 请求参数
     * @param  cookieStore
     * @return 如果请求异常，直接返回Map
     **/
    private static Map postUrlContent(String url, Map<String, String> params,
                                      CookieStore cookieStore) {
        Map<String, Object> map = new HashMap<String, Object>();
        // if enable ssl
        // TODO
        // pls check this url
        // http://hc.apache.org/httpcomponents-client-ga/httpclient/examples/org/apache/http/examples/client/ClientCustomSSL.java
        // end ssl
        // Create a local instance of cookie store
        if (cookieStore == null) {
            cookieStore = new BasicCookieStore();
        }
        try {
            HttpPost httpReq = new HttpPost(url);
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("Executing Post request url{},url lenth {}", httpReq.getRequestLine(),
                        httpReq.getRequestLine().getUri().length());
            }
            // 组装POST请求参数
            if (params != null && !params.isEmpty()) {
                // check post 方式
                if (null != params.get(CONTENT_TYPE_KEY)
                        && params.get(CONTENT_TYPE_KEY).equalsIgnoreCase(
                        ContentType.APPLICATION_JSON.getMimeType())
                        && null != params.get(JSON_STR_KEY)) {// JSON
                    // POST
                    httpReq.setHeader("Content-type", ContentType.APPLICATION_JSON.getMimeType());
                    httpReq.setEntity(new StringEntity(params.get(JSON_STR_KEY), Consts.UTF_8
                            .displayName()));
                } else {
                    List<NameValuePair> nvps = new ArrayList<NameValuePair>();

                    for (Iterator<Entry<String, String>> it = params.entrySet().iterator(); it
                            .hasNext(); ) {
                        Entry entry = it.next();

                        if (null == entry.getKey() || null == entry.getValue()) {
                            continue;
                        }

                        String key = (String) entry.getKey();
                        nvps.add(new BasicNameValuePair(key, (String) entry.getValue()));
                    }
                    // 对参数已经编码处理
                    httpReq.setEntity(new UrlEncodedFormEntity(nvps, Consts.UTF_8.displayName()));
                }
            }

            // TODO Auto-generated catch block

            return processContent(httpReq, cookieStore, Consts.UTF_8.displayName());
        } catch (IOException e) {
            e.printStackTrace();
            if (LOGGER.isErrorEnabled()) {
                LOGGER.error("POST请求失败", e);
            }
        }
        return map;
    }

    /**
     * 多个URL请求，需要共享cookie
     * @param urlMap 就是请求的地址 value就是请求参数,并且value本身也是一个map ,键就是参数名称,value是参数值
     * @return 最后一次请求的返回值，如果请求异常，返回null
     ***/
    public static String getMutiUrlReq(LinkedHashMap<String, Map<String, String>> urlMap) {
        if (urlMap != null) {
            CookieStore cookie = null;
            for (Iterator<Entry<String, Map<String, String>>> it = urlMap.entrySet().iterator(); it
                    .hasNext(); ) {
                Entry entry = it.next();
                String url = (String) entry.getKey();
                Map param = (Map) entry.getValue();
                if (cookie == null) {
                    cookie = (CookieStore) postUrlContent(url, param, null).get(RES_COOKIE_KEY);
                } else {
                    return (String) postUrlContent(url, param, cookie).get(RES_RESULT_KEY);
                }
            }
        }
        return null;
    }

    /**
     * 数据返回的处理
     ***/

    private static Map processContent(HttpRequestBase get,/* Map<String, Object> map, */
                                      CookieStore cookieStore, String encoding) throws ClientProtocolException, IOException {
        Map<String, Object> map = new HashMap();
        String responseString = null;
        // Create local HTTP context
        HttpClientContext localContext = HttpClientContext.create();
        // Bind custom cookie store to the local context
        localContext.setCookieStore(cookieStore);
        try {
            CloseableHttpResponse response = httpClient.execute(get, localContext);
            // 检查返回状态，如果是跳转状态，需要重新请求跳转地址
            int status = response.getStatusLine().getStatusCode();
            if ((status == HttpStatus.SC_MOVED_TEMPORARILY) ||

                    (status == HttpStatus.SC_MOVED_PERMANENTLY) ||

                    (status == HttpStatus.SC_SEE_OTHER) ||

                    (status == HttpStatus.SC_TEMPORARY_REDIRECT)) {
                String redirectUrl = response.getFirstHeader("location").getValue();
                if (LOGGER.isDebugEnabled()) {
                    LOGGER.debug("要请求跳转地址 url{}", redirectUrl);
                }
                if (redirectUrl != null) {
                    get.setURI(new URI(redirectUrl));
                    // 再请求一次
                    response = httpClient.execute(get, localContext);
                }
            }


            try {
                HttpEntity entity = response.getEntity();
                try {
                    if (entity != null) {
                        responseString = EntityUtils.toString(entity, encoding);
                    }
                } finally {
                    if (entity != null) {
                        entity.getContent().close();
                    }
                }
            } catch (Exception e) {
                LOGGER.error(
                        String.format("[NetUtils Get]get response error, url:%s", get.getURI()), e);
            } finally {
                if (response != null) {
                    response.close();
                }
            }
        } catch (SocketTimeoutException e) {
            LOGGER.error(
                    String.format("[NetUtils Get]invoke get timout error, url:%s", get.getURI()), e);
        } catch (Exception e) {
            LOGGER.error(String.format("[NetUtils Get]invoke get error, url:%s", get.getURI()), e);
        } finally {
            get.releaseConnection();
        }
        // 设置返回结果值
        map.put(RES_COOKIE_KEY, cookieStore);
        map.put(RES_RESULT_KEY, responseString);
        return map;
    }
}

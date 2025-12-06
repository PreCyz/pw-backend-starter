package pw.react.backend.services;

import lombok.extern.slf4j.Slf4j;
import org.springframework.web.client.RestTemplate;

@Slf4j
public class HttpBaseService implements HttpService {

    private final RestTemplate restTemplate;

    public HttpBaseService(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    @Override
    public Object consume(String url) {
        final Object object = restTemplate.getForObject(url, String.class);
        if (object != null) {
            log.info("This is Quote: {}", object);
        } else {
            log.warn("Quote is null");
        }
        return object;
    }
}

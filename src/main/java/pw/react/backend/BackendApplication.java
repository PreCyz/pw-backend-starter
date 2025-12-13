package pw.react.backend;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ApplicationListener;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Profile;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.web.client.RestTemplate;

@Slf4j
@SpringBootApplication
public class BackendApplication {
	static void main(String[] args) {
		SpringApplication.run(BackendApplication.class, args);
	}

	@Bean
	@Profile("it")
	AotCacheFeeder aotCacheFeeder(RestTemplate restTemplate,
								  @Value("${app.port}") String serverPort,
								  @Value("${app.actuator.port}") String actuatorPort) {
		AotCacheFeeder aotCacheFeeder = new AotCacheFeeder(restTemplate, serverPort, actuatorPort);
//		aotCacheFeeder.execute();
		return aotCacheFeeder;
	}

	@Bean
	@Profile("it")
	public ContextStartedListener contextStartedListener(final AotCacheFeeder aotCacheFeeder) {
		return new ContextStartedListener(aotCacheFeeder);
	}

	@RequiredArgsConstructor
	public static class ContextStartedListener implements ApplicationListener<ContextRefreshedEvent> {

		private final AotCacheFeeder aotCacheFeeder;

		@Override
		public void onApplicationEvent(ContextRefreshedEvent event) {
			log.info("Context Refreshed Event received. {}", event);
			aotCacheFeeder.execute();
			log.info("AOT cache warmed up. Shutting down application.");
			System.exit(0);
		}
	}

}

package pw.react.backend.config;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import java.util.function.Supplier;
import java.util.stream.Stream;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.web.client.RestTemplate;
import pw.react.backend.dto.request.CreateCompanyRequest;
import pw.react.backend.dto.request.UpdateCompanyRequest;
import pw.react.backend.dto.response.CompanyResponse;
import pw.react.backend.dto.response.GetCompanyResponse;

@Configuration
@Slf4j
public class StartOptimizerConfig {

    @Bean
    @Profile("aot-warm-up")
    public ApplicationListener<ContextRefreshedEvent> contextRefreshedListener(
            RestTemplate restTemplate,
            @Value("${server.port}") String serverPort,
            @Value("${management.server.port}") String actuatorPort
    ) {
        return event -> {
            log.info("Context Refreshed Event received. {}", event);
            try {
                new AotCacheFeeder(restTemplate, serverPort, actuatorPort).execute();
                log.info("AOT cache warmed up.");
            } catch (Exception e) {
                log.error("AOT cache warm up finished prematurely. {}", e.getMessage());
            } finally {
                log.info("Shutting down application.");
            }
            System.exit(0);
        };
    }

    @Bean
    @Profile("first-request")
    public ApplicationListener<ApplicationReadyEvent> applicationReadyListener(
            final RestTemplate restTemplate,
            @Value("${server.port}") final String serverPort,
            @Value("${management.server.port}") final String actuatorPort
    ) {
        return event -> {
            log.info("Application Ready Event received. {}", event);
            try {
                new AotCacheFeeder(restTemplate, serverPort, actuatorPort).executeWarmUp();
                log.info("Warm up API path done.");
            } catch (Exception e) {
                log.error("Warm up API finished prematurely. {}", e.getMessage());
            }
        };
    }

    @Slf4j
    public static class AotCacheFeeder {
        private final RestTemplate restTemplate;

        private final String baseUrl;

        private final String actuatorUrl;

        public AotCacheFeeder(RestTemplate restTemplate, String basePort, String actuatorPort) {
            this.restTemplate = restTemplate;
            this.baseUrl = "http://localhost:%s".formatted(basePort);
            this.actuatorUrl = "http://localhost:%s".formatted(actuatorPort);
        }

        public void execute() {
            createCompanies(5);
        }

        private void createCompanies(int limit) {
            Supplier<CreateCompanyRequest> createCompanyRequestSupplier = () -> {
                var ccr = new CreateCompanyRequest();
                ccr.setName(UUID.randomUUID().toString());
                ccr.setStartDate(LocalDateTime.now());
                ccr.setBoardMembers(2);
                return ccr;
            };
            List<CreateCompanyRequest> companies = Stream.generate(createCompanyRequestSupplier).limit(limit).toList();
            CompanyResponse[] companyIds = restTemplate.postForObject(
                    "%s/companies".formatted(baseUrl), companies, CompanyResponse[].class
            );
            log.info("Created companies {}", companyIds);


            if (companyIds != null) {
                getPageOfCompanies();
                List<CompanyResponse> ids = Arrays.stream(companyIds).toList();
                getAllCompanies(ids);
                deleteCompany(ids);
            }
        }

        private void getAllCompanies(List<CompanyResponse> ids) {
            List<GetCompanyResponse> companyIds = new ArrayList<>(ids.size());
            for (CompanyResponse company : ids) {
                GetCompanyResponse forObject = restTemplate.getForObject(
                        "%s/companies/%d".formatted(baseUrl, company.getId()), GetCompanyResponse.class
                );
                companyIds.add(forObject);
                log.info("Retrieved companies {}", forObject);
            }

            updateCompany(companyIds);
        }

        private void getPageOfCompanies() {
            GetCompanyResponse[] companyIds = restTemplate.getForObject(
                    "%s/companies?size=10&page=1".formatted(baseUrl), GetCompanyResponse[].class
            );
            log.info("Retrieved page of companies companies {}", companyIds);
        }

        private void updateCompany(List<GetCompanyResponse> companies) {
            for (GetCompanyResponse company : companies) {
                UpdateCompanyRequest updateCompanyRequest = new UpdateCompanyRequest();
                updateCompanyRequest.setName("warm_up_updated" + company.getName());
                updateCompanyRequest.setBoardMembers(company.getBoardMembers());
                restTemplate.put("%s/companies/%d".formatted(baseUrl, company.getId()), updateCompanyRequest);
            }
            log.info("Updated companies {}", companies);
        }

        private void deleteCompany(List<CompanyResponse> companyIds) {
            companyIds.forEach(company -> restTemplate.delete("%s/companies/%d".formatted(baseUrl, company.getId())));
            log.info("Deleted companies {}", companyIds);
        }

        private void actuatorHealth(int limit) {
            List<String> responses = new ArrayList<>(limit);
            for (int i = 0; i < limit; i++) {
                String response = restTemplate.getForObject("%s/actuator/health".formatted(actuatorUrl), String.class);
                responses.add("Health -> " + response);
            }
            log.info("Health {}", responses);
        }

        private void actuatorEnv(int limit) {
            List<String> responses = new ArrayList<>(limit);
            for (int i = 0; i < limit; i++) {
                String response = restTemplate.getForObject("%s/actuator/env".formatted(actuatorUrl), String.class);
                responses.add("Env -> " + response);
            }
            log.info("Env {}", responses);
        }

        public void executeWarmUp() {
            createCompanies(1);
//            actuatorHealth(1);
//            actuatorEnv(1);
        }
    }
}

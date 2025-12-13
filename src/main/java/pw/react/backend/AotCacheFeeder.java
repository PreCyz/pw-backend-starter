package pw.react.backend;

import lombok.extern.slf4j.Slf4j;
import org.springframework.web.client.RestTemplate;
import pw.react.backend.dto.request.CreateCompanyRequest;
import pw.react.backend.dto.request.UpdateCompanyRequest;
import pw.react.backend.dto.response.CompanyResponse;
import pw.react.backend.dto.response.GetCompanyResponse;

import java.time.LocalDateTime;
import java.util.*;
import java.util.function.Supplier;
import java.util.stream.Stream;

@Slf4j
public class AotCacheFeeder {
    private final RestTemplate restTemplate;
    private final String baseUrl;
    private final String actuatorUrl;

    public AotCacheFeeder(RestTemplate restTemplate, String basePort,  String actuatorPort) {
        this.restTemplate = restTemplate;
        this.baseUrl = "http://localhost:%s".formatted(basePort);
        this.actuatorUrl = "http://localhost:%s".formatted(actuatorPort);
    }

    public void execute() {
        createCompanies();
        actuatorHealth();
        actuatorEnv();
    }

    private void createCompanies() {
        Supplier<CreateCompanyRequest> createCompanyRequestSupplier = () -> {
            var ccr = new CreateCompanyRequest();
            ccr.setName(UUID.randomUUID().toString());
            ccr.setStartDate(LocalDateTime.now());
            ccr.setBoardMembers(2);
            return ccr;
        };
        List<CreateCompanyRequest> companies = Stream.generate(createCompanyRequestSupplier).limit(5).toList();
        CompanyResponse[] companyIds = restTemplate.postForObject(
                "%s/companies".formatted(this.baseUrl), companies, CompanyResponse[].class
        );
        log.info("Created companies {}", companyIds);


        if (companyIds != null) {
            List<CompanyResponse> ids = Arrays.stream(companyIds).toList();
            getAllCompanies(ids);
            deleteCompany(ids);
        }
    }

    private void getAllCompanies(List<CompanyResponse> ids) {
        GetCompanyResponse[] companyIds = restTemplate.getForObject(
                "%s/companies".formatted(this.baseUrl), GetCompanyResponse[].class
        );
        log.info("Retrieved companies {}", companyIds);

        updateCompany(companyIds);

        for (CompanyResponse company : ids) {
            GetCompanyResponse forObject = restTemplate.getForObject(
                    "%s/companies/%d".formatted(this.baseUrl, company.getId()), GetCompanyResponse.class
            );
            log.info("Retrieved companies {}", forObject);
        }
    }

    private void updateCompany(GetCompanyResponse[] companies) {
        for (GetCompanyResponse company : companies) {
            UpdateCompanyRequest updateCompanyRequest = new UpdateCompanyRequest();
            updateCompanyRequest.setName("updated_" + company.getName());
            updateCompanyRequest.setBoardMembers(company.getBoardMembers());
            restTemplate.put("%s/companies/%d".formatted(this.baseUrl, company.getId()), updateCompanyRequest);
        }
        log.info("Updated companies {}", companies);
    }

    private void deleteCompany(List<CompanyResponse> companyIds) {
        companyIds.forEach(company -> restTemplate.delete("%s/companies/%d".formatted(this.baseUrl, company.getId())));
        log.info("Deleted companies {}", companyIds);
    }

    private void actuatorHealth() {

    }

    private void actuatorEnv() {

    }
}

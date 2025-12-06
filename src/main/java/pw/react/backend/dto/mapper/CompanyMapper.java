package pw.react.backend.dto.mapper;

import org.mapstruct.*;
import pw.react.backend.domain.Company;
import pw.react.backend.dto.inbound.CreateCompanyRequest;
import pw.react.backend.dto.inbound.UpdateCompanyRequest;
import pw.react.backend.dto.outbound.CompanyResponse;

import java.util.List;

@Mapper(unmappedTargetPolicy = ReportingPolicy.IGNORE)
public interface CompanyMapper {
    @Mapping(target = "startDateTime", source = "createCompanyRequest.startDate")
    Company createRequestToCompany(CreateCompanyRequest createCompanyRequest);
    List<Company> createRequestToCompanyList(List<CreateCompanyRequest> createCompanyRequests);

    CompanyResponse companyToResponse(Company company);
    List<CompanyResponse> companyToResponseList(List<Company> company);

    Company updateRequestToCompany(UpdateCompanyRequest updateCompanyRequest);
}

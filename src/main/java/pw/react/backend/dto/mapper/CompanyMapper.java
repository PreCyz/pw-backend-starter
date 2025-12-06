package pw.react.backend.dto.mapper;

import org.mapstruct.*;
import pw.react.backend.domain.Company;
import pw.react.backend.dto.inbound.CompanyRequest;
import pw.react.backend.dto.outbound.CompanyResponse;

import java.util.List;

@Mapper(unmappedTargetPolicy = ReportingPolicy.IGNORE)
public interface CompanyMapper {
    @Mapping(target = "startDateTime", source = "companyRequest.startDate")
    Company requestToCompany(CompanyRequest companyRequest);
    List<Company> requestsToCompanyList(List<CompanyRequest> companyRequests);
    CompanyResponse companyToResponse(Company company);
    List<CompanyResponse> companyToResponseList(List<Company> company);
}

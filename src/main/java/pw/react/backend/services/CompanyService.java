package pw.react.backend.services;

import pw.react.backend.domain.Company;
import pw.react.backend.exceptions.ResourceNotFoundException;

import java.util.List;
import java.util.Optional;

public interface CompanyService {
    Company updateCompany(Long id, Company updatedCompany) throws ResourceNotFoundException;
    boolean deleteCompany(Long companyId);
    List<Company> batchSave(List<Company> companies);
    Optional<Company> getById(long companyId);
    List<Company> getAll();
    List<Company> getCompaniesPage(int page, int size);
}

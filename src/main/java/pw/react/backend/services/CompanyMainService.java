package pw.react.backend.services;

import java.util.Collections;
import java.util.List;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.PageRequest;
import pw.react.backend.domain.Company;
import pw.react.backend.exceptions.ResourceNotFoundException;
import pw.react.backend.repositories.CompanyRepository;

@Slf4j
@RequiredArgsConstructor
public class CompanyMainService implements CompanyService {

    private final CompanyRepository repository;

    @Override
    public Company updateCompany(Long id, Company updatedCompany) throws ResourceNotFoundException {
        Company company = repository.getReferenceById(id);
        company.setName(updatedCompany.getName());
        company.setBoardMembers(updatedCompany.getBoardMembers());
        Company result = repository.save(company);
        log.info("Company with id {} updated.", id);
        return result;
    }

    @Override
    public boolean deleteCompany(Long companyId) {
        boolean result = false;
//        if (repository.existsById(companyId)) {
            repository.deleteById(companyId);
            log.info("Company with id {} deleted.", companyId);
            result = true;
//        }
        return result;
    }

    @Override
    public List<Company> batchSave(List<Company> companies) {
        if (companies != null && !companies.isEmpty()) {
            return repository.saveAll(companies);
        } else {
            log.warn("Companies collection is empty or null.");
            return Collections.emptyList();
        }
    }

    @Override
    public Optional<Company> getById(long companyId) {
        return repository.findById(companyId);
    }

    @Override
    public List<Company> getAll() {
        return repository.findAll();
    }

    @Override
    public List<Company> getCompaniesPage(int pageNumber, int pageSize) {
        int defaultPageSize = 10;
        return repository.findAll(PageRequest.of(pageNumber, pageSize == 0 ? defaultPageSize : pageSize)).getContent();
    }
}

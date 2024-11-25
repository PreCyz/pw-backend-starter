package pw.react.backend.services;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pw.react.backend.dao.CompanyRepository;
import pw.react.backend.exceptions.ResourceNotFoundException;
import pw.react.backend.models.Company;

import java.util.*;

public class CompanyMainService implements CompanyService {
    private final Logger logger = LoggerFactory.getLogger(CompanyMainService.class);

    private final CompanyRepository repository;

    protected CompanyMainService(CompanyRepository repository) {
        this.repository = repository;
    }

    @Override
    public Company updateCompany(Long id, Company updatedCompany) throws ResourceNotFoundException {
        if (repository.existsById(id)) {
            updatedCompany.setId(id);
            Company result = repository.save(updatedCompany);
            logger.info("Company with id {} updated.", id);
            return result;
        }
        throw new ResourceNotFoundException(String.format("Company with id [%d] not found.", id));
    }

    @Override
    public boolean deleteCompany(Long companyId) {
        boolean result = false;
        if (repository.existsById(companyId)) {
            repository.deleteById(companyId);
            logger.info("Company with id {} deleted.", companyId);
            result = true;
        }
        return result;
    }

    @Override
    public Collection<Company> batchSave(Collection<Company> companies) {
        if (companies != null && !companies.isEmpty()) {
            return repository.saveAll(companies);
        } else {
            logger.warn("Companies collection is empty or null.");
            return Collections.emptyList();
        }
    }

    @Override
    public Optional<Company> getById(long companyId) {
        return repository.findById(companyId);
    }

    @Override
    public Collection<Company> getAll() {
        return repository.findAll();
    }
}

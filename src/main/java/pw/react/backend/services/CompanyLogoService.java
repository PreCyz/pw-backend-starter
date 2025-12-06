package pw.react.backend.services;

import lombok.extern.slf4j.Slf4j;
import org.springframework.util.StringUtils;
import org.springframework.web.multipart.MultipartFile;
import pw.react.backend.domain.CompanyLogo;
import pw.react.backend.exceptions.InvalidFileException;
import pw.react.backend.exceptions.ResourceNotFoundException;
import pw.react.backend.repositories.CompanyLogoRepository;

import java.io.IOException;

@Slf4j
public class CompanyLogoService {

    private final CompanyLogoRepository repository;

    public CompanyLogoService(CompanyLogoRepository repository) {
        this.repository = repository;
    }

    public CompanyLogo storeLogo(long companyId, MultipartFile file) {
        // Normalize file name
        String fileName = StringUtils.cleanPath(file.getOriginalFilename());

        try {
            // Check if the file's name contains invalid characters
            if (fileName.contains("..")) {
                throw new InvalidFileException("Sorry! Filename contains invalid path sequence " + fileName);
            }

            CompanyLogo newCompanyLogo = new CompanyLogo(fileName, file.getContentType(), companyId, file.getBytes());
            repository.findByCompanyId(companyId).ifPresent(companyLogo -> newCompanyLogo.setId(companyLogo.getId()));
            return repository.save(newCompanyLogo);
        } catch (IOException ex) {
            throw new InvalidFileException("Could not store file " + fileName + ". Please try again!", ex);
        }
    }

    public CompanyLogo getCompanyLogo(long companyId) {
        return repository.findByCompanyId(companyId)
                .orElseThrow(() -> new ResourceNotFoundException("File not found with companyId " + companyId));
    }

    public void deleteCompanyLogo(long companyId) {
        repository.deleteByCompanyId(companyId);
        log.info("Logo for the company with id {} deleted.", companyId);
    }
}

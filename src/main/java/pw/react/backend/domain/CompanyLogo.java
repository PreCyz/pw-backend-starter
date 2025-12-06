package pw.react.backend.domain;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(name = "company_logo")
@NoArgsConstructor
@Getter
@Setter
public class CompanyLogo {

    @Id
    @GeneratedValue(generator = "uuid")
    private String id;
    private String fileName;
    private String fileType;
    private long companyId;
    @Lob
    private byte[] data;

    public CompanyLogo(String fileName, String fileType, long companyId, byte[] data) {
        this.fileName = fileName;
        this.fileType = fileType;
        this.companyId = companyId;
        this.data = data;
    }
}

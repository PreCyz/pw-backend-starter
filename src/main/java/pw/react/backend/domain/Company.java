package pw.react.backend.domain;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.io.Serial;
import java.io.Serializable;
import java.time.LocalDateTime;

@Entity
@Table(name = "company")
@Getter
@Setter
public class Company implements Serializable {

    @Serial
    private static final long serialVersionUID = -6783504532088859179L;

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long id;
    @Column
    private String name;
    @Column(name = "start_date")
    private LocalDateTime startDateTime;
    /**
     * By default, the column name in the database is going to be board_members
     */
    @Column
    private int boardMembers;
}

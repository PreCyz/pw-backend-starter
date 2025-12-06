package pw.react.backend.repositories;

import java.util.List;

public interface BatchRepository<T> {
    List<T> insertAll(List<T> entities);
}

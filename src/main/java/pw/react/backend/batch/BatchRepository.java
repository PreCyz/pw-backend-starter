package pw.react.backend.batch;

import java.util.List;

public interface BatchRepository<T> {
    List<T> insertAll(List<T> entities);
}

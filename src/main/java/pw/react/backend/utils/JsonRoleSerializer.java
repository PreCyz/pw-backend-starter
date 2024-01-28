package pw.react.backend.utils;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;

import java.io.IOException;
import java.util.Collection;

import static java.util.stream.Collectors.joining;

public class JsonRoleSerializer extends JsonSerializer<Collection<String>> {

    @Override
    public void serialize(Collection<String> roles, JsonGenerator jsonGenerator, SerializerProvider serializerProvider) throws IOException {
        String roleStr = roles.stream()
                .map(it -> it.replaceAll("ROLE_", ""))
                .collect(joining(","));
        jsonGenerator.writeString(roleStr);
    }
}

package pw.react.backend.utils;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.ObjectCodec;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.node.ArrayNode;
import pw.react.backend.models.Role;

import java.io.IOException;
import java.util.*;

public class JsonRoleDeserializer extends JsonDeserializer<Collection<String>> {

    @Override
    public Collection<String> deserialize(JsonParser jp, DeserializationContext ctxt) throws IOException {
        ObjectCodec oc = jp.getCodec();
        ArrayNode node = oc.readTree(jp);
        Set<String> roles = new HashSet<>(node.size());
        for (int i = 0; i< node.size(); i++) {
            roles.add(Role.Value.valueFrom(node.get(i).asText()));
        }
        return roles;
    }
}

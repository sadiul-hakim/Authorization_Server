package org.authorization_server.model;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.AttributeConverter;
import org.springframework.stereotype.Component;

import java.util.Collections;
import java.util.List;

@Component
public class StringListConverter implements AttributeConverter<List<String>, String> {
    private final ObjectMapper mapper = new ObjectMapper();

    @Override
    public String convertToDatabaseColumn(List<String> attribute) {
        try {
            return mapper.writeValueAsString(attribute);
        } catch (Exception ex) {
            return null;
        }
    }

    @Override
    public List<String> convertToEntityAttribute(String dbData) {
        try {
            return mapper.readValue(dbData, new TypeReference<>() {
            });
        } catch (Exception ex) {
            return Collections.emptyList();
        }
    }
}

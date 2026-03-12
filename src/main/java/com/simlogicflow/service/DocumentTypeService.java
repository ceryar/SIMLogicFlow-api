package com.simlogicflow.service;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.simlogicflow.dto.DocumentTypeDto;
import com.simlogicflow.model.DocumentType;
import com.simlogicflow.repository.DocumentTypeRepository;

@Service
public class DocumentTypeService {

    @Autowired
    private DocumentTypeRepository documentTypeRepository;

    public List<DocumentType> getAllDocumentTypes() {
        return documentTypeRepository.findAll();
    }

    public DocumentType createDocumentType(DocumentTypeDto dto) {
        DocumentType documentType = new DocumentType();
        updateDocumentTypeFromDto(documentType, dto);
        return documentTypeRepository.save(documentType);
    }

    public DocumentType updateDocumentType(Long id, DocumentTypeDto dto) {
        Optional<DocumentType> optionalDocumentType = documentTypeRepository.findById(id);
        if (optionalDocumentType.isPresent()) {
            DocumentType documentType = optionalDocumentType.get();
            updateDocumentTypeFromDto(documentType, dto);
            return documentTypeRepository.save(documentType);
        }
        throw new RuntimeException("DocumentType not found with id " + id);
    }

    public void deleteDocumentType(Long id) {
        documentTypeRepository.deleteById(id);
    }

    private void updateDocumentTypeFromDto(DocumentType documentType, DocumentTypeDto dto) {
        documentType.setName(dto.getName());
    }
}

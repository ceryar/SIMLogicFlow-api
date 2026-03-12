package com.simlogicflow.dto;


import lombok.*;
@Getter // para que la clase Lombook cree kis get
@Setter // para que la clase Lombook cree kis set
@NoArgsConstructor // crea construtor sin parametros
@AllArgsConstructor // constructor con parametros 
public class LoginDto {
    private String email;
    private String password;

     public void setPassword(String password) {
        this.password = password;
    }

}

package io.security.springsecuritymaster.users.repository;

import io.security.springsecuritymaster.domain.entity.Account;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends JpaRepository<Account, Long> {
}

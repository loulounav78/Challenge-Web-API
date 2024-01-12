<?php

namespace App\Entity;

use ApiPlatform\Metadata\ApiFilter;
use ApiPlatform\Metadata\ApiProperty;
use ApiPlatform\Metadata\ApiResource;
use ApiPlatform\Metadata\Delete;
use ApiPlatform\Metadata\Get;
use ApiPlatform\Metadata\GetCollection;
use ApiPlatform\Metadata\Patch;
use ApiPlatform\Metadata\Post;
use ApiPlatform\Metadata\Put;
use ApiPlatform\Doctrine\Orm\Filter\SearchFilter;
use ApiPlatform\Doctrine\Orm\Filter\NumericFilter;
use ApiPlatform\Doctrine\Orm\Filter\ExistsFilter;
use Symfony\Component\Validator\Constraints\Length;
use Symfony\Component\Validator\Constraints\Regex;
use Doctrine\ORM\Mapping as ORM;
use App\Repository\UserRepository;
use Symfony\Bridge\Doctrine\Validator\Constraints\UniqueEntity;
use Symfony\Component\Security\Core\User\PasswordAuthenticatedUserInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Serializer\Annotation\Groups;
use Symfony\Component\Validator\Constraints as Assert;

#[ApiResource(
    operations: [
        new GetCollection(),
        new Post(
            validationContext: ['groups' => ['Default', 'user:create']]
        ),
        new Get(security:"object == user"),
        new Put(),//security:"object == user"),
        new Patch(security:"previous_object == user"),
        new Delete(),//security:"object == user"),
    ],
    normalizationContext: ['groups' => ['user:read']],
    denormalizationContext: ['groups' => ['user:create', 'user:update']],
)]
#[ApiFilter(SearchFilter::class, properties: ["username" => "exact", "email" => "exact"])]
#[ApiFilter(NumericFilter::class, properties: ["id"])]
//#[ApiFilter(ExistsFilter::class, properties: ["email"], denormalizationContext: ["exists" => false])]

#[ORM\Entity(repositoryClass: UserRepository::class)]
#[UniqueEntity('email')]
class User implements UserInterface
{
    #[Groups(['user:read'])]
    #[ORM\Id]
    #[ORM\Column(type: 'integer')]
    #[ORM\GeneratedValue]
    private ?int $id = null;

    #[Groups(['user:create'])]
    #[ORM\Column(type: 'string',length: 255)]
    #[Assert\NotBlank]
    #[Assert\Regex("/^[a-zA-ZÀ-ÿ]+$/", message:"Le nom ne doit contenir que des lettres.")]
    private ?string $username = null;

    #[Assert\NotBlank]
    #[Assert\Email]
    #[Groups(['user:read', 'user:create', 'user:update'])]
    #[ORM\Column(length: 255, unique: true)]
    private ?string $email = null;

    #[Assert\Length(min:8, minMessage:"Le mot de passe doit faire au moins 8 caractères.")]
    #[Assert\NotBlank(groups: ['user:create'])]
    #[Groups(['user:create', 'user:update'])]
    #[ORM\Column]
    private ?string $password = null;

    public function getRoles(): array
    {
        return ['ROLE_USER'];
    }

    public function eraseCredentials(): void
    {
        // Méthode appelée après l'authentification pour effacer des informations sensibles.
        // Par exemple, si vous stockez des informations sensibles dans l'entité.
    }

    public function getSalt(): ?string
    {
        // Vous n'avez pas besoin de sel si vous utilisez bcrypt comme algorithme de hachage du mot de passe.
        return null;
    }
    public function getUserIdentifier(): string
    {
        return (string) $this->username;
    }
    // Getter and Setter methods

    public function getId(): ?int
    {
        return $this->id;
    }

    public function getUsername(): string
    {
        return $this->username;
    }

    public function setUsername(string $username): self
    {
        $this->username = $username;

        return $this;
    }

    public function getEmail(): string
    {
        return $this->email;
    }

    public function setEmail(string $email): self
    {
        $this->email = $email;

        return $this;
    }

    public function getPassword(): string
    {
        return $this->password;
    }

    public function setPassword(string $password): self
    {
        // Hasher le mot de passe avant de le stocker dans la base de données
        $this->password = password_hash($password, PASSWORD_BCRYPT);
        return $this;
    }

    // Méthodes supplémentaires pour UserInterface (si nécessaire)
    // ...

    // Vous pouvez également ajouter des méthodes pour les opérations CRUD spécifiques.
    // Par exemple, pour l'opération POST (inscription) :
    public function onPrePersist(): void
    {
        // Ajoutez ici les conditions supplémentaires pour l'inscription
        // (vérification de l'email unique, longueur du mot de passe, etc.)
    }
}

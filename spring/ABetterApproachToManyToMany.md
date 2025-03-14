# Defining many-to-many relationships using an explicit junction entity

## Problem

Spring Data JPA offers an annotation for many-to-many mappings, at `jakarta.persistence.ManyToMany`.
This is useful for simple cases where there is no additional information bound to the relationship; however,
in cases where there _is_ additional information needed to fully describe the relationship,
this solution is insufficient.

Consider an issue tracking system, like Jira. Many users can be assigned to an issue and many issues can be
assigned to a user. We should also track when an issue was assigned to a user, so the junction table will have
an additional field, `assigned_at`. Using the `ManyToMany` annotation here will be insufficient as it won't allow
us to customize the junction table.

## Solution

Proceeding with the issue tracker example, let's define a many-to-many relationship
between a `User` and `Issue` entity.

Start by defining the entities (3rd party imports have been excluded):

#### User.java

```java
import io.onicodes.issue_tracker.models.issueAssignee.IssueAssignee;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Entity
@Table(name = "users")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Setter(AccessLevel.NONE)
    private Long id;

    @Column(nullable = false)
    private String name;

    @Column(nullable = false, unique = true)
    private String email;

    @OneToMany(mappedBy = "user")
    private Set<IssueAssignee> issues;
}
```

#### Issue.java

```java
import io.onicodes.issue_tracker.models.issueAssignee.IssueAssignee;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Entity
@Table(name = "issues")
public class Issue {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Setter(AccessLevel.NONE)
    private Long id;

    @NotBlank
    @Column(nullable = false)
    private String title;

    @NotBlank
    @Column(columnDefinition = "TEXT", nullable = false)
    private String description;

    @Column(nullable = false)
    private LocalDateTime createdAt = LocalDateTime.now();

    @Column(nullable = false)
    private LocalDateTime updatedAt = LocalDateTime.now();

    @OneToMany(mappedBy = "issue")
    private Set<IssueAssignee> assignees;
}
```

The `OneToMany` annotated attributes on both `User` and `Issue` are referencing attributes on the junction entity,
`IssueAssignee`, via the _mappedBy_ argument. Let's define this junction entity now.

#### IssueAssignee.java

```java
import io.onicodes.issue_tracker.models.User;
import io.onicodes.issue_tracker.models.issue.Issue;

@NoArgsConstructor
@Getter
@Setter
@Entity
@Table(name = "issue_assignees")
public class IssueAssignee {
    @EmbeddedId
    @Setter(AccessLevel.NONE)
    private IssueAssigneeId id;

    @ManyToOne
    @MapsId("issueId")
    @JoinColumn(name = "issue_id")
    private Issue issue; // gets referenced in Issue entity OneToMany attribute

    @ManyToOne
    @MapsId("userId")
    @JoinColumn(name = "user_id")
    private User user; // gets referenced in User entity OneToMany attribute

    @Column(nullable = false)
    private LocalDateTime assignedAt = LocalDateTime.now();

    public IssueAssignee(Issue issue, User user) {
        this.issue = issue;
        this.user = user;
        this.id = new IssueAssigneeId(issue.getId(), user.getId());
    }
}
```

There are a few new annotations here: `EmbeddedId` (more later), `ManyToOne`, `MapsId`, and `JoinColumn`.

1. `ManyToOne` -> tells Data JPA that **many** IssueAssignees can be associated to **one** issue/user
2. `MapsId` -> references a field that is used to build the composite primary key (the `EmbeddedId` id)
3. `JoinColumn` -> gives explicit name to the column used in the junction table (otherwise Spring uses defaults)

Wrapping `IssueAssignee.id` in `EmbeddedId` is necessary since it represents a composite primary key. Let's
define the `IssueAssigneeId` type.

```java
import java.io.Serializable;

@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode
@Getter
@Setter
@Embeddable
public class IssueAssigneeId implements Serializable {
    // These attributes are what get referenced by the @MapsId annotations in IssueAssignee entity
    private Long issueId;
    private Long userId;
}
```

Note that types meant to represent composite key fields must implement `Serializable` and
be wrapped in `@Embeddable`; this is what allows them to be wrapped in the `@EmbeddedId`
annotation later.

Create the repositories to make data access easy.

```java
import io.onicodes.issue_tracker.models.issue.Issue;

public interface IssuesRepository extends JpaRepository<Issue, Long> {

}
```

Access data through getters and setters (as provisioned by lombok annotations in the examples above):

#### Example request mapping for getting all assignees for a given issue id

```java
// ...
    @GetMapping("/{id}/assignees")
    public List<UserDTO> assignees(@PathVariable Long id) {
        return issuesRepository
                    .findById(id)
                    .orElseThrow(() -> new IssueNotFoundException(id))
                    .getAssignees()
                    .stream()
                    .map(a -> new UserDTO(a.getUser()))
                    .collect(Collectors.toList());
    }
// ...
```

# Problem

A common pattern in Spring apps is to have the service and controller layers communicate
by passing Data Transfer Objects (DTOs) to one another. The DTO object is a lightweight
representation of some persisted data/soon-to-be persisted data. This is more ideal than
passing around entire entities for performance reasons and it allows more control over how
the controllers consume/provide data to the clients.

Moreover, there may be technical constraints that make it cumbersome/impossible for an entity
to be parsed to json; for example, [ABetterApproachToManyToMany.md](ABetterApproachToManyToMany.md) describes
a many-to-many relationship between an Issue and User entity, with an IssueAssignee junction entity between them.
The Issue entity has a field for IssueAssignees, which also contains a field reference to Issue. Parsing
this circular relationship to json leads to a stack overflow error due to the maximum recursion depth being reached.

## Solution

Rather than working directly with entity objects, the controller layer should only interact with
DTOs. This keeps the controller lightweight and independent of any entity implementations.

Avoid hardcoding the DTO mapping like this:

#### Issue entity

```java
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@ToString
@Entity
@Table(name = "issues")
public class Issue {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotBlank
    @Column(nullable = false)
    private String title;

    @Column(columnDefinition = "TEXT", nullable = false)
    private String description;

    @Convert(converter = IssueStatusConverter.class)
    @Column(nullable = false)
    private IssueStatus status;

    @Convert(converter = IssuePriorityConverter.class)
    @Column(nullable = false)
    private IssuePriority priority;

    @Column(nullable = false)
    private LocalDateTime createdAt = LocalDateTime.now();

    @Column(nullable = false)
    private LocalDateTime updatedAt = LocalDateTime.now();

    @OneToMany(mappedBy = "issue", cascade = CascadeType.ALL, orphanRemoval = true)
    private Set<IssueAssignee> assignees = new HashSet<>();
}
```

#### Example hardcoded DTO mapping for Issue entity

```java
public class IssueCreateRequestDTO {
    private String title;
    private String description;
    private String status;
    private String priority;
    private List<UserDTO> assignees;

    public IssueCreateRequestDTO(Issue issue) {
        this.title = issue.getTitle();
        this.description = issue.getDescription();
        this.status = issue.getStatus().name(); // manually converting from enum to string
        this.priority = issue.getPriority().name(); // manually converting from enum to string
        this.assignees = issue.getAssignees()
                                    .stream()
                                    .map(assignee -> new UserDTO(assignee.getUser()))
                                    .collect(Collectors.toList());
    }
}
```

The above DTO could represent a request body the client sends to the server
to create a new Issue. Hardcoding the mapping like this is error prone and liable to drift
away from the entity it's trying to map (a field is added to the entity but not added to the
DTO and vice versa). Moreover, now the DTO and entity are tightly coupled.

A better approach is to delegate the mapping responsibility to a separate Mapper class.
[MapStruct](https://mapstruct.org/) is a popular option.

```java
@Mapper
public interface IssueMapper {

    IssueMapper INSTANCE = Mappers.getMapper(IssueMapper.class);

    @Mapping(target = "id", ignore = true)
    @Mapping(target = "assignees", ignore = true)
    @Mapping(target = "createdAt", ignore = true)
    @Mapping(target = "updatedAt", ignore = true)
    Issue issueCreateRequestDTOToIssue(IssueCreateRequestDTO issueDTO);

    IssueResponseDTO issueToIssueDTO(Issue issue);

    UserDTO userToUserDTO(User user);

    default UserDTO issueAssigneeToUserDTO(IssueAssignee assignee) {
        return userToUserDTO(assignee.getUser());
    }

}
```

MapStruct is a code generator; it uses the interface above to generate a concrete implementation
of the mapper at compile time. MapStruct follows a convention over configuration approach; some
appropriate convention is used to map from one type to anothas;lkasier in most cases, depending on the input
and output type. In the example above, we didn't have to explicitly tell MapStruct to convert the enums
IssueStatus and IssuePriority to their name counterparts; it will do so automatically. We also didn't
explicitly tell it to handle the mapping from a Set of IssueAssignees to a List of UserDTOs; we simply
defined how to convert from an IssueAssignee to a UserDTO, MapStruct already knows how to convert from a
Set to a List.

Understanding the annotations above:

1. Mapper -> wraps the interface and tells MapStruct to generate a mapper using it
2. Mapping -> configure how certain attributes with different names should be handled or ignored if applicable

#### Example POST request using new DTOs

```java
// IssueController

    @PostMapping
    public IssueResponseDTO createIssue(@RequestBody IssueCreateRequestDTO issueDTO) {
        return issueService.createIssue(issueDTO);
    }

// ...

// IssueService

    @Transactional
    public IssueResponseDTO createIssue(IssueCreateRequestDTO issueDTO) {
        Issue issue = issueRepository
                        .save(IssueMapper.INSTANCE.issueCreateRequestDTOToIssue(issueDTO));
        List<Long> userIds = issueDTO
                                .getAssignees()
                                .stream()
                                .map(userDTO -> userDTO.getId())
                                .collect(Collectors.toList());

        issueAssigneeService.assign(userIds, issue);
        return IssueMapper.INSTANCE.issueToIssueDTO(issue);
    }
```

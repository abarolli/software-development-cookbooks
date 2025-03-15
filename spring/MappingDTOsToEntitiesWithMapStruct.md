# Problem

A common pattern in Spring apps is to have the service and controller layers communicate
by passing Data Transfer Objects (DTOs) to one another. The DTO object is a lightweight
representation of some persisted data/soon-to-be persisted data. This is more ideal than
passing around entire entities for performance reasons and it allows more control over how
the controllers consume/provide data to the clients.

Moreover, there may be technical constraints that make it cumbersome/impossible for an entity
to be parsed to json;for example, [ABetterApproachToManyToMany.md](ABetterApproachToManyToMany.md) describes
a many-to-many relationship between an Issue and User entity, with an IssueAssignee junction entity between them.
The Issue entity has a field for IssueAssignees, which also contains a field reference to Issue. This circular
relationship leads to a stack overflow error due to the maximum recursion depth being reached.

## Solution

Rather than working directly with entity objects, the controller layer should only interact with
DTOs. This keeps the controller lightweight and independent of any entity implementations.

Avoid hardcoding the DTO mapping like this:

#### Example hardcoded DTO mapping for Issue

```java
public class IssueDTO {
    private String title;
    private String description;
    private String status;
    private String priority;
    private List<UserDTO> assignees = new ArrayList<>();

    public IssueDTO(Issue issue) {
        this.title = issue.getTitle();
        this.description = issue.getDescription();
        this.status = issue.getStatus().name(); // manually converting from enum to string
        this.priority = issue.getPriority().name(); // manually converting from enum to string
        this.assignees = issue.getAssignees().
                                    .stream()
                                    .map(assignee -> new UserDTO(assignee.getUser()))
                                    .collect(Collectors.toList());
    }
}
```

This approach is error prone and liable to drift away from the entity it's trying to map (a field is
added to the entity but not added to the DTO and vice versa). Moreover, now the DTO and entity are
tightly coupled.

A better approach is to delegate the mapping responsibility to a separate Mapper class.

class CreateButton extends StatelessWidget {
  @override
  Widget build(BuildContext context) => Padding(
    child: FlowyOptionTile.text(
      content: Expanded(child: Text('Create')),
    ),
  );
}
